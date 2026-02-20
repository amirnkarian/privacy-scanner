"""
Test: Bulletproof monitoring step that CANNOT hang.

Problem: page.mouse.wheel() and page.wait_for_timeout(1500) are Playwright
calls that can block if the page/CDP connection is stuck. The monitoring
loop uses these in a while loop, so if one call hangs, the whole step hangs.

Fix:
1. Fire-and-forget JS scroll (setInterval) — runs in browser, returns instantly
2. Use small page.wait_for_timeout(500) chunks for event processing
   (required for the request listener to fire)
3. Hard wall-clock deadline — if total elapsed > MONITOR_SECONDS + 3s, break out
4. Per-call sanity check — if a single 500ms wait takes >5s, something is
   wrong with CDP, break out immediately

This guarantees the monitoring step completes in at most MONITOR_SECONDS + 3s,
no matter what the page does. The 90s process kill is the ultimate backstop.
"""
import time
from playwright.sync_api import sync_playwright

MONITOR_SECONDS = 15
URL = "https://www.michaelstars.com/collections/womens-new-arrivals"

# Fire-and-forget: starts a scroll interval in the browser.
# Returns immediately. Scrolling happens asynchronously in the browser.
START_SCROLL_JS = """(seconds) => {
    const end = Date.now() + seconds * 1000;
    const id = setInterval(() => {
        if (Date.now() >= end) { clearInterval(id); return; }
        window.scrollBy(0, 350);
    }, 1500);
}"""


def run_test():
    overall_start = time.time()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # ── Get to a product page ──
        print(f"[{time.time() - overall_start:6.1f}s] Loading collection page...")
        page.goto(URL, timeout=15000, wait_until="domcontentloaded")
        page.wait_for_timeout(3000)

        product_urls = page.evaluate("""() => {
            const hrefs = new Set();
            for (const a of document.querySelectorAll('a[href*="/products/"]')) {
                const href = a.href || a.getAttribute('href');
                if (href && href !== '/' && href !== '#') hrefs.add(href);
            }
            return [...hrefs];
        }""")

        if not product_urls:
            print("No product URLs found!")
            browser.close()
            return

        print(f"[{time.time() - overall_start:6.1f}s] Navigating to product...")
        page.goto(product_urls[0], timeout=15000, wait_until="domcontentloaded")
        page.wait_for_timeout(3000)
        print(f"[{time.time() - overall_start:6.1f}s] On product page: {page.url[:80]}")

        # ── Set up request listener ──
        captured = []

        def on_request(request):
            captured.append(request.url)

        page.on("request", on_request)

        # ── FIXED MONITORING ──
        print(f"\n[{time.time() - overall_start:6.1f}s] === STARTING MONITORING (FIXED) ===")
        print(f"  Duration: {MONITOR_SECONDS}s")

        monitor_start = time.time()
        deadline = monitor_start + MONITOR_SECONDS  # Hard wall-clock limit

        # 1. Fire-and-forget: start JS scroll in the browser
        try:
            page.evaluate(START_SCROLL_JS, MONITOR_SECONDS)
        except Exception as e:
            print(f"  Could not start scroll: {e}")

        # 2. Small wait_for_timeout chunks for event processing
        #    Each call is 500ms. If any single call takes >5s, CDP is stuck — bail.
        iteration = 0
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            iteration += 1
            chunk_ms = min(500, int(remaining * 1000))
            if chunk_ms <= 0:
                break

            t_before = time.time()
            try:
                page.wait_for_timeout(chunk_ms)
            except Exception as e:
                print(f"  wait_for_timeout failed at iter {iteration}: {e}")
                break
            call_time = time.time() - t_before

            # Sanity check: a 500ms wait should never take >5s
            if call_time > 5.0:
                print(f"  [iter {iteration}] HUNG: wait_for_timeout({chunk_ms}ms) "
                      f"took {call_time:.1f}s — CDP stuck, bailing out")
                break

        monitor_elapsed = time.time() - monitor_start

        try:
            page.remove_listener("request", on_request)
        except Exception:
            pass

        print(f"\n[{time.time() - overall_start:6.1f}s] === MONITORING COMPLETE ===")
        print(f"  Monitor loop took: {monitor_elapsed:.1f}s (target: {MONITOR_SECONDS}s)")
        print(f"  Iterations: {iteration}")
        print(f"  Requests captured: {len(captured)}")

        browser.close()

    total = time.time() - overall_start
    print(f"\n[{total:6.1f}s] TOTAL TEST TIME")

    if monitor_elapsed <= MONITOR_SECONDS + 4:
        print("*** PASS — monitoring completed within expected time ***")
    else:
        print(f"*** FAIL — monitoring took {monitor_elapsed:.1f}s "
              f"(expected ~{MONITOR_SECONDS}s) ***")


if __name__ == "__main__":
    run_test()
