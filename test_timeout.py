"""
Proof that multiprocessing.Process + kill() can terminate a stuck Playwright browser.
"""
import multiprocessing
import time


def stuck_playwright(result_queue):
    """Simulates a scan that hangs forever inside Playwright."""
    from playwright.sync_api import sync_playwright
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto("https://example.com", timeout=5000)
            print("[child] Page loaded. Now hanging forever...")
            page.wait_for_timeout(999999)  # THIS WILL HANG
            # Should never reach here
            print("[child] ERROR: wait_for_timeout returned (should not happen)")
            result_queue.put("COMPLETED")
    except Exception as e:
        result_queue.put(f"ERROR: {e}")


if __name__ == "__main__":
    TIMEOUT = 10  # seconds

    print(f"[test] Starting stuck Playwright process with {TIMEOUT}s timeout...")
    start = time.time()

    result_queue = multiprocessing.Queue()
    proc = multiprocessing.Process(target=stuck_playwright, args=(result_queue,))
    proc.start()
    proc.join(timeout=TIMEOUT)

    elapsed = time.time() - start

    if proc.is_alive():
        print(f"[test] Process still alive after {elapsed:.1f}s — killing with SIGKILL...")
        proc.kill()
        proc.join()
        elapsed = time.time() - start
        print(f"[test] Process killed after {elapsed:.1f}s")
        print(f"\n*** TIMEOUT WORKED ***")
    else:
        result = result_queue.get(timeout=2) if not result_queue.empty() else "NO RESULT"
        print(f"[test] Process exited on its own after {elapsed:.1f}s: {result}")
        print(f"\n*** TEST FAILED — process was not stuck ***")
