"""
scanner.py - Main privacy compliance scanner.

This script visits websites, looks for cookie opt-out buttons, clicks them,
and then checks whether tracking actually stopped. Results are saved to a
SQLite database via database.py.

Usage:
    python scanner.py https://example.com https://other.com
    python scanner.py --file urls.txt
    python scanner.py                      (reads urls.txt by default)
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

import database

# ────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────────────

# Where screenshots are saved.
SCREENSHOTS_DIR = "screenshots"

# How long (ms) to wait for a page to load before giving up.
PAGE_LOAD_TIMEOUT = 60_000  # 60 seconds

# How long (seconds) to wait after clicking opt-out for the site to adjust.
POST_OPTOUT_WAIT = 30

# How long (seconds) to monitor network traffic after the opt-out wait.
POST_OPTOUT_MONITOR = 15

# ────────────────────────────────────────────────────────────────────
# KNOWN TRACKER DOMAINS
#
# If a network request goes to any of these domains, we flag it as a
# tracker. This list covers the most common analytics, advertising,
# and session-recording services.
# ────────────────────────────────────────────────────────────────────

TRACKER_DOMAINS = [
    # Google
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "googlesyndication.com",
    # Meta / Facebook
    "connect.facebook.net",
    "facebook.net",
    "graph.facebook.com",
    # Microsoft
    "clarity.ms",
    "bat.bing.com",
    # Session recording & analytics
    "hotjar.com",
    "mixpanel.com",
    "segment.com",
    "amplitude.com",
    "fullstory.com",
    "crazyegg.com",
    "mouseflow.com",
    # Marketing platforms
    "hubspot.com",
    "marketo.com",
    "pardot.com",
    # Pinterest
    "ct.pinterest.com",
    # LinkedIn
    "px.ads.linkedin.com",
    # Snapchat
    "sc-static.net",
    "tr.snapchat.com",
    "us-central1-ct.snap.com",
    # Reddit
    "ads.reddit.com",
    "alb.reddit.com",
    "events.reddit.com",
    # TikTok
    "analytics.tiktok.com",
    "business-api.tiktok.com",
    # Twitter / X
    "analytics.twitter.com",
    "ads-api.twitter.com",
    # Criteo
    "criteo.com",
    "criteo.net",
    # Taboola
    "taboola.com",
    # Outbrain
    "outbrain.com",
    # Klaviyo
    "klaviyo.com",
    # Attentive
    "attn.tv",
    "attentivemobile.com",
    # Affiliate / tracking
    "tp.media",
    "impact.com",
    "linksynergy.com",
    "shareasale.com",
]

# Some trackers live at specific paths on larger domains.  We check
# both the domain AND the path fragment for these.
TRACKER_URL_PATTERNS = [
    "tiktok.com/analytics",
    "www.tiktok.com/api",
    "linkedin.com/insight",
    "snap.licdn.com",
    "pinterest.com/tag",
    "twitter.com/i/adsct",
    "www.facebook.com/tr",
    "pixel.facebook.com",
    # t.co is Twitter's tracking redirect — matched with slashes to
    # avoid false positives on words containing "t.co".
    "//t.co/",
]

# ────────────────────────────────────────────────────────────────────
# COOKIE OPT-OUT BUTTON LABELS
#
# We search the page for buttons/links whose visible text matches
# one of these (case-insensitive).  They are ordered from most
# explicit ("Reject All") to least ("Manage Preferences").
# ────────────────────────────────────────────────────────────────────

# Primary buttons — a single click should opt out.
PRIMARY_OPTOUT_TEXTS = [
    "Reject All",
    "Reject all",
    "Decline All",
    "Decline all",
    "Decline",
    "Opt Out",
    "Opt out",
    "Only Essential",
    "Only essential",
    "Necessary Only",
    "Necessary only",
    "Deny All",
    "Deny all",
    "Deny",
    "Refuse All",
    "Refuse all",
]

# Fallback — opens a settings panel where we then look for a
# "save" or "confirm" button with minimal cookies selected.
MANAGE_PREFS_TEXTS = [
    "Manage Preferences",
    "Manage preferences",
    "Cookie Settings",
    "Cookie settings",
    "Manage Cookies",
    "Manage cookies",
    "Cookie Manager",
    "Your Privacy Choices",
    "Do Not Sell My Personal Information",
    "Do Not Sell or Share",
    "Manage consent",
    "Manage Consent",
    "Customize",
    "More Options",
    "More options",
]

# Inside the preferences panel, look for these to confirm opt-out.
SAVE_MINIMAL_TEXTS = [
    "Reject All",
    "Reject all",
    "Refuse All",
    "Refuse all",
    "Reject Targeting and Marketing",
    "Confirm My Choices",
    "Confirm my choices",
    "Save",
    "Confirm",
    "Confirm Choices",
    "Confirm choices",
    "Save Preferences",
    "Save preferences",
    "Accept Selected",
    "Accept selected",
    "Save Settings",
    "Save settings",
]


# ────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ────────────────────────────────────────────────────────────────────

def get_domain(url):
    """Extract the domain name from a URL (e.g. 'www.example.com')."""
    return urlparse(url).netloc or url


def is_tracker_request(request_url):
    """
    Check if a network request URL matches a known tracker.

    Returns the matched tracker domain/pattern string, or None.
    """
    # Check full domain matches — the request URL must contain the
    # tracker domain somewhere in it.
    for domain in TRACKER_DOMAINS:
        if domain in request_url:
            return domain

    # Check path-specific patterns (e.g. "tiktok.com/analytics").
    for pattern in TRACKER_URL_PATTERNS:
        if pattern in request_url:
            return pattern

    return None


def find_third_party_cookies(cookies, site_domain):
    """
    Given a list of browser cookies, return those that don't belong
    to the site being scanned (i.e. third-party cookies).
    """
    third_party = []
    for cookie in cookies:
        cookie_domain = cookie.get("domain", "").lstrip(".")
        # A cookie is third-party if its domain isn't part of the
        # site we're visiting.
        if site_domain not in cookie_domain and cookie_domain not in site_domain:
            third_party.append(cookie)
    return third_party


def collect_tracker_hits(captured_requests):
    """
    Scan a list of captured request URLs and return a sorted list of
    unique tracker domains that were contacted.
    """
    found = set()
    for url in captured_requests:
        match = is_tracker_request(url)
        if match:
            found.add(match)
    return sorted(found)


def try_click_button(page, button_texts, timeout=3000):
    """
    Try to find and click a visible button/link matching one of the
    given text labels.

    Returns the matched text if a button was clicked, or None.
    """
    for text in button_texts:
        try:
            # Build a selector that finds buttons, links, or elements
            # with role="button" whose visible text matches.
            # We use get_by_role and get_by_text for reliability.
            for selector in [
                f'button:has-text("{text}")',
                f'a:has-text("{text}")',
                f'[role="button"]:has-text("{text}")',
                f'input[value="{text}" i]',
            ]:
                locator = page.locator(selector).first
                if locator.is_visible(timeout=500):
                    locator.click(timeout=timeout)
                    return text
        except Exception:
            # This text/selector combo didn't work — try the next one.
            continue
    return None


# ────────────────────────────────────────────────────────────────────
# COOKIE OPT-OUT: MULTI-STRATEGY SYSTEM
# ────────────────────────────────────────────────────────────────────

# Selectors for known cookie consent framework banners.
_BANNER_SELECTORS = [
    '#onetrust-banner-sdk',
    '#CybotCookiebotDialog',
    '.truste-consent-track',
    '#truste-consent-track',
    '.osano-cm-window',
    '[class*="cookie-banner"]',
    '[class*="consent-banner"]',
    '[id*="cookie-banner"]',
    '[id*="consent-banner"]',
]

# Footer link texts for finding privacy/cookie preference links.
_FOOTER_PRIVACY_TEXTS = [
    "Your Privacy Choices",
    "Do Not Sell",
    "Do Not Sell My Personal Information",
    "Do Not Sell or Share",
    "Privacy",
    "Cookie",
    "Cookie Preferences",
    "Cookie Settings",
]


def _is_banner_dismissed(page):
    """Check if the cookie consent banner has been dismissed."""
    for selector in _BANNER_SELECTORS:
        try:
            el = page.query_selector(selector)
            if el and el.is_visible():
                return False
        except Exception:
            continue
    return True


def _safe_click(page, selector, timeout=3000):
    """Try to click a selector if it exists and is visible. Returns True on success."""
    try:
        locator = page.locator(selector).first
        if locator.is_visible(timeout=500):
            locator.click(timeout=timeout)
            return True
    except Exception:
        pass
    return False


def _try_framework_optout(page):
    """
    Strategy 1: Framework-specific selectors (OneTrust, CookieBot, TrustArc, Osano).
    Returns dict with keys: strategy, clicked, element, verified.
    """
    attempt = {"strategy": "framework_specific", "clicked": False, "element": None}

    # ── OneTrust ──────────────────────────────────────────────
    try:
        banner = page.query_selector('#onetrust-banner-sdk')
        if banner and banner.is_visible():
            # Try direct reject button first
            if _safe_click(page, '#onetrust-reject-all-handler'):
                attempt["clicked"] = True
                attempt["element"] = "OneTrust: Reject All"
                return attempt

            # Try opening preference center, then reject-all inside it
            if _safe_click(page, '#onetrust-pc-btn-handler'):
                page.wait_for_timeout(2000)
                # Try reject-all in preference center
                if _safe_click(page, '.ot-pc-refuse-all-handler'):
                    attempt["clicked"] = True
                    attempt["element"] = "OneTrust: Preference Center → Reject All"
                    return attempt
                # Try save/confirm in preference center (toggles may default to off)
                clicked_save = try_click_button(page, SAVE_MINIMAL_TEXTS)
                if clicked_save:
                    attempt["clicked"] = True
                    attempt["element"] = f"OneTrust: Preference Center → {clicked_save}"
                    return attempt
                # Try the save-preference button directly
                if _safe_click(page, 'button.save-preference-btn-handler'):
                    attempt["clicked"] = True
                    attempt["element"] = "OneTrust: Preference Center → Save Preferences"
                    return attempt
    except Exception:
        pass

    # ── CookieBot ─────────────────────────────────────────────
    try:
        banner = page.query_selector('#CybotCookiebotDialog')
        if banner and banner.is_visible():
            if _safe_click(page, '#CybotCookiebotDialogBodyButtonDecline'):
                attempt["clicked"] = True
                attempt["element"] = "CookieBot: Decline"
                return attempt
            # Try customize → then reject/save
            if _safe_click(page, '#CybotCookiebotDialogBodyLevelButtonCustomize'):
                page.wait_for_timeout(1500)
                if _safe_click(page, '#CybotCookiebotDialogBodyButtonDecline'):
                    attempt["clicked"] = True
                    attempt["element"] = "CookieBot: Customize → Decline"
                    return attempt
    except Exception:
        pass

    # ── TrustArc ──────────────────────────────────────────────
    try:
        for sel in ['.truste-consent-track', '#truste-consent-track']:
            banner = page.query_selector(sel)
            if banner and banner.is_visible():
                if _safe_click(page, '.truste-consent-required'):
                    attempt["clicked"] = True
                    attempt["element"] = "TrustArc: Required Only"
                    return attempt
                if _safe_click(page, '.truste-consent-button'):
                    page.wait_for_timeout(2000)
                    clicked_save = try_click_button(page, SAVE_MINIMAL_TEXTS)
                    if clicked_save:
                        attempt["clicked"] = True
                        attempt["element"] = f"TrustArc: Preferences → {clicked_save}"
                        return attempt
    except Exception:
        pass

    # ── Osano ─────────────────────────────────────────────────
    try:
        banner = page.query_selector('.osano-cm-window')
        if banner and banner.is_visible():
            if _safe_click(page, '.osano-cm-deny'):
                attempt["clicked"] = True
                attempt["element"] = "Osano: Deny"
                return attempt
    except Exception:
        pass

    return attempt


def _try_toggle_optout(page):
    """
    Strategy 3: Open manage preferences, disable toggles, save.
    Returns dict with keys: strategy, clicked, element.
    """
    attempt = {"strategy": "manage_prefs_toggles", "clicked": False, "element": None}

    manage_clicked = try_click_button(page, MANAGE_PREFS_TEXTS)
    if not manage_clicked:
        return attempt

    print(f'[*] Clicked preferences button: "{manage_clicked}"')
    page.wait_for_timeout(2000)

    # Try to disable checked toggles inside preference panels.
    toggle_selectors = [
        'input[type="checkbox"]:checked',
        '[aria-checked="true"]',
        '.ot-switch input:checked',
    ]
    toggles_flipped = 0
    for sel in toggle_selectors:
        try:
            toggles = page.locator(sel)
            count = toggles.count()
            for i in range(count):
                try:
                    toggle = toggles.nth(i)
                    if toggle.is_visible(timeout=300):
                        toggle.click(timeout=1000)
                        toggles_flipped += 1
                except Exception:
                    continue
        except Exception:
            continue

    if toggles_flipped > 0:
        print(f"[*] Disabled {toggles_flipped} toggle(s) in preferences panel.")

    # Now click save/confirm
    save_clicked = try_click_button(page, SAVE_MINIMAL_TEXTS)
    if save_clicked:
        attempt["clicked"] = True
        attempt["element"] = f"Manage Preferences ({manage_clicked}) → {save_clicked}"
        if toggles_flipped > 0:
            attempt["element"] += f" (disabled {toggles_flipped} toggles)"
    elif toggles_flipped > 0:
        # Try clicking the save button by selector as a last resort
        if _safe_click(page, 'button.save-preference-btn-handler'):
            attempt["clicked"] = True
            attempt["element"] = f"Manage Preferences ({manage_clicked}) → Save (disabled {toggles_flipped} toggles)"

    return attempt


def _try_footer_privacy_link(page):
    """
    Strategy 4: Look for a privacy/cookie link in the footer and try opt-out there.
    Returns dict with keys: strategy, clicked, element.
    """
    attempt = {"strategy": "footer_link", "clicked": False, "element": None}

    for text in _FOOTER_PRIVACY_TEXTS:
        try:
            for selector in [
                f'footer a:has-text("{text}")',
                f'a:has-text("{text}")',
                f'[role="link"]:has-text("{text}")',
            ]:
                locator = page.locator(selector).first
                if locator.is_visible(timeout=500):
                    locator.click(timeout=3000)
                    print(f'[*] Clicked footer privacy link: "{text}"')
                    page.wait_for_timeout(2500)

                    # Now try framework-specific opt-out on the new modal/page
                    fw_attempt = _try_framework_optout(page)
                    if fw_attempt["clicked"]:
                        attempt["clicked"] = True
                        attempt["element"] = f"Footer ({text}) → {fw_attempt['element']}"
                        return attempt

                    # Try direct text buttons
                    direct = try_click_button(page, PRIMARY_OPTOUT_TEXTS)
                    if direct:
                        attempt["clicked"] = True
                        attempt["element"] = f"Footer ({text}) → {direct}"
                        return attempt

                    # Try toggle approach
                    toggle_attempt = _try_toggle_optout(page)
                    if toggle_attempt["clicked"]:
                        attempt["clicked"] = True
                        attempt["element"] = f"Footer ({text}) → {toggle_attempt['element']}"
                        return attempt

                    # Tried this link but nothing worked — continue to next
                    break
        except Exception:
            continue

    return attempt


def attempt_cookie_optout(page, domain):
    """
    Multi-strategy cookie opt-out system.

    Tries multiple strategies in order and verifies success by checking
    if the consent banner is dismissed after each attempt.

    Returns a dict with:
      - opt_out_found: "yes" | "no"
      - opt_out_clicked: "yes" | "no"
      - opt_out_verified: "yes" | "no"
      - opt_out_method: description of what worked
      - opt_out_attempts: list of attempt dicts
    """
    results = {
        "opt_out_found": "no",
        "opt_out_clicked": "no",
        "opt_out_verified": "no",
        "opt_out_method": None,
        "opt_out_attempts": [],
    }

    strategies = [
        ("Framework-Specific", _try_framework_optout),
        ("Direct Text Buttons", lambda p: {
            "strategy": "direct_text",
            "clicked": bool(try_click_button(p, PRIMARY_OPTOUT_TEXTS)),
            "element": try_click_button(p, PRIMARY_OPTOUT_TEXTS),
        }),
        ("Manage Preferences + Toggles", _try_toggle_optout),
        ("Footer Privacy Link", _try_footer_privacy_link),
    ]

    # For strategy 2, we need a wrapper that doesn't double-click
    def _direct_text_strategy(p):
        clicked = try_click_button(p, PRIMARY_OPTOUT_TEXTS)
        return {
            "strategy": "direct_text",
            "clicked": bool(clicked),
            "element": clicked,
        }

    strategies[1] = ("Direct Text Buttons", _direct_text_strategy)

    for name, strategy_fn in strategies:
        print(f"[*] Trying opt-out strategy: {name}...")
        try:
            attempt = strategy_fn(page)
        except Exception as e:
            print(f"[!] Strategy {name} raised error: {e}")
            attempt = {"strategy": name, "clicked": False, "element": None}

        results["opt_out_attempts"].append(attempt)

        if attempt.get("clicked"):
            results["opt_out_found"] = "yes"
            results["opt_out_clicked"] = "yes"
            print(f'[*] Opt-out clicked via {name}: {attempt.get("element")}')

            # Wait for banner to animate away
            page.wait_for_timeout(2000)

            if _is_banner_dismissed(page):
                results["opt_out_verified"] = "yes"
                results["opt_out_method"] = attempt.get("element", name)
                print(f"[*] Banner dismissed — opt-out verified!")
                break
            else:
                print(f"[!] Banner still visible after {name} — trying next strategy...")
        else:
            print(f"[*] Strategy {name} did not find anything to click.")

    # Last resort: try dismissing any remaining overlay
    if results["opt_out_verified"] != "yes":
        for selector in ['#onetrust-accept-btn-handler', '.cookie-close',
                         '[class*="dismiss"]', '.close-button', '[aria-label="Close"]']:
            try:
                if _safe_click(page, selector):
                    page.wait_for_timeout(1500)
                    if _is_banner_dismissed(page):
                        results["opt_out_found"] = "yes"
                        results["opt_out_clicked"] = "yes"
                        results["opt_out_verified"] = "yes"
                        results["opt_out_method"] = f"Dismissed overlay via {selector}"
                        print(f"[*] Dismissed overlay via {selector}")
                        break
            except Exception:
                continue

    return results


# ────────────────────────────────────────────────────────────────────
# SCREENSHOT HELPER
# ────────────────────────────────────────────────────────────────────

def _take_optout_screenshot(page, safe_domain):
    """Take a screenshot after opt-out attempt for verification."""
    path = os.path.join(SCREENSHOTS_DIR, f"{safe_domain}_optout.png")
    try:
        page.screenshot(path=path, full_page=False)
        return path
    except Exception:
        return None


# Labels we look for when trying to navigate to the shop/products page.
SHOP_LINK_TEXTS = [
    "Shop All",
    "Shop all",
    "shop all",
    "Shop Now",
    "Shop now",
    "All Products",
    "All products",
    "Products",
    "Collections",
    "New Arrivals",
    "New arrivals",
    "new arrivals",
    "Shop",
    "Catalog",
    "Store",
    "Browse",
]


def navigate_to_shop(page):
    """
    Try to find and click a link to the shop / all-products page.

    Returns the link text that was clicked, or None if nothing was found.
    """
    for text in SHOP_LINK_TEXTS:
        try:
            # Look for navigation links — typically in the header/nav.
            for selector in [
                f'nav a:has-text("{text}")',
                f'header a:has-text("{text}")',
                f'a:has-text("{text}")',
                f'[role="link"]:has-text("{text}")',
            ]:
                locator = page.locator(selector).first
                if locator.is_visible(timeout=500):
                    locator.click(timeout=5000)
                    return text
        except Exception:
            continue
    return None


def click_first_product(page):
    """
    On a shop/collection page, find and click the first product link.

    Tries common product card selectors used by Shopify, custom stores,
    and other e-commerce platforms.

    Returns True if a product was clicked, False otherwise.
    """
    # Common selectors for product cards / product links.
    product_selectors = [
        # Shopify themes
        '.product-card a[href*="/products/"]',
        '.product-grid-item a[href*="/products/"]',
        '.grid__item a[href*="/products/"]',
        'a.product-card[href*="/products/"]',
        # Generic product links (plural and singular paths)
        'a[href*="/products/"]',
        'a[href*="/product/"]',
        'a[href*="/shop/"]',
        'a[href*="/p/"]',
        'a[href*="/dp/"]',
        'a[href*="/item/"]',
        # Product cards with images (common pattern)
        '.product a',
        '.product-item a',
        '.collection-product a',
        '[data-product] a',
        '.product-tile a',
        '.product-list a',
        # Grid-based layouts
        '.grid-product a',
        '.product-grid a',
    ]

    for selector in product_selectors:
        try:
            locator = page.locator(selector).first
            if locator.is_visible(timeout=500):
                locator.click(timeout=5000)
                return True
        except Exception:
            continue

    return False


def group_requests_by_domain(captured_requests):
    """
    Group all captured request URLs by their domain and return a dict.

    Useful for seeing exactly which domains the browser talked to
    and how many requests went to each.
    """
    from collections import Counter
    domains = Counter()
    for url in captured_requests:
        try:
            domain = urlparse(url).netloc
            if domain:
                domains[domain] += 1
        except Exception:
            pass
    # Sort by request count (most first).
    return dict(sorted(domains.items(), key=lambda x: -x[1]))


# ────────────────────────────────────────────────────────────────────
# MAIN SCAN FUNCTION
# ────────────────────────────────────────────────────────────────────

def scan_url(browser, url, status_callback=None):
    """
    Perform a full privacy compliance scan on a single URL.

    Args:
        browser:         A Playwright Browser instance.
        url:             The full URL to scan (e.g. "https://example.com").
        status_callback: Optional function(message, step, total_steps) called
                         at each major checkpoint.  Used by the web UI to
                         stream real-time progress via SSE.

    Returns:
        A dict summarising the scan results.
    """
    TOTAL_STEPS = 17

    # We'll collect results as we go and return them at the end.
    results = {
        "url": url,
        "opt_out_found": "no",
        "opt_out_clicked": "no",
        "trackers_before": [],
        "trackers_after": [],
        "still_tracking": "no",
        "screenshot_before": None,
        "screenshot_after": None,
        "screenshot_viewport": None,
        "notes": [],
        # Enhanced data capture for evidence package.
        "cookies_before_details": [],
        "cookies_after_details": [],
        "new_cookies_details": [],
        "request_details": [],
        "scan_timeline": [],
        # Cookie opt-out verification data.
        "opt_out_verified": "no",
        "opt_out_method": None,
        "opt_out_attempts": [],
    }

    def report_status(message, step):
        """Send a status update via the callback, if one was provided."""
        results["scan_timeline"].append({
            "step": step,
            "message": message,
            "timestamp": datetime.now().isoformat(),
        })
        if status_callback:
            status_callback(message, step, TOTAL_STEPS)

    domain = get_domain(url)
    print(f"\n{'=' * 60}")
    print(f"  SCANNING: {url}")
    print(f"{'=' * 60}")
    report_status(f"Initializing scan for {domain}", 1)

    # ── Step 1: Open a new browser tab ──────────────────────────────
    # Each URL gets its own isolated browser context so cookies and
    # storage from one site don't leak into another.
    context = browser.new_context(
        viewport={"width": 1280, "height": 900},
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
    )
    page = context.new_page()

    # ── Step 2: Start network monitoring ────────────────────────────
    # Every time the browser makes a network request (images, scripts,
    # API calls, tracking pixels, etc.), we record the URL.
    captured_requests = []
    request_details = []

    def on_request(request):
        captured_requests.append(request.url)
        try:
            headers = dict(request.headers) if request.headers else {}
        except Exception:
            headers = {}
        try:
            post_data_length = len(request.post_data) if request.post_data else 0
        except Exception:
            post_data_length = 0
        request_details.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
            "post_data_length": post_data_length,
            "timestamp": time.time(),
            "headers": headers,
        })

    page.on("request", on_request)
    print("[*] Network monitoring started.")
    report_status("Visiting website...", 2)

    # ── Step 3: Navigate to the website ─────────────────────────────
    try:
        page.goto(url, timeout=PAGE_LOAD_TIMEOUT, wait_until="networkidle")
        print(f"[*] Page loaded: {url}")
        report_status("Page loaded successfully", 3)
    except PlaywrightTimeout:
        print(f"[!] Page load timed out after {PAGE_LOAD_TIMEOUT // 1000}s — "
              "continuing with what we have.")
        results["notes"].append("Page load timed out.")
    except Exception as e:
        print(f"[!] Error loading page: {e}")
        results["notes"].append(f"Page load error: {e}")
        context.close()
        return results

    # Give any lazy-loaded scripts a moment to fire.
    page.wait_for_timeout(3000)

    # ── Step 4: Take "before" screenshot ────────────────────────────
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    safe_domain = domain.replace(":", "_")  # handle ports in domain
    before_path = os.path.join(SCREENSHOTS_DIR, f"{safe_domain}_before.png")
    try:
        page.screenshot(path=before_path, full_page=True)
        results["screenshot_before"] = before_path
        print(f"[*] 'Before' screenshot saved: {before_path}")
        report_status("Before screenshot captured", 4)
    except Exception as e:
        print(f"[!] Screenshot failed: {e}")

    # ── Step 5: Record initial trackers ─────────────────────────────
    # Check every request we captured against our tracker list.
    results["trackers_before"] = collect_tracker_hits(captured_requests)

    # Also check for third-party cookies.
    all_cookies = context.cookies()
    results["cookies_before_details"] = all_cookies
    tp_cookies_before = find_third_party_cookies(all_cookies, domain)

    if results["trackers_before"]:
        print(f"[*] Trackers found BEFORE opt-out ({len(results['trackers_before'])}):")
        for t in results["trackers_before"]:
            print(f"      - {t}")
        report_status(f"Initial trackers identified: {len(results['trackers_before'])} found", 5)
    else:
        print("[*] No known trackers detected before opt-out.")
        report_status("No known trackers detected on initial load", 5)

    if tp_cookies_before:
        cookie_domains = sorted({c["domain"] for c in tp_cookies_before})
        print(f"[*] Third-party cookies found ({len(tp_cookies_before)}):")
        for d in cookie_domains:
            print(f"      - {d}")
        results["notes"].append(
            f"Third-party cookies before opt-out: {json.dumps(cookie_domains)}"
        )

    # ── Step 6: Find and click the opt-out button ───────────────────
    print("[*] Looking for cookie consent opt-out button...")
    report_status("Looking for cookie consent opt-out button...", 6)

    optout_result = attempt_cookie_optout(page, domain)
    results["opt_out_found"] = optout_result["opt_out_found"]
    results["opt_out_clicked"] = optout_result["opt_out_clicked"]
    results["opt_out_verified"] = optout_result["opt_out_verified"]
    results["opt_out_method"] = optout_result["opt_out_method"]
    results["opt_out_attempts"] = optout_result["opt_out_attempts"]

    # Take screenshot after opt-out attempt for verification.
    optout_screenshot = _take_optout_screenshot(page, safe_domain)
    if optout_screenshot:
        results["screenshot_optout"] = optout_screenshot

    if results["opt_out_verified"] == "yes":
        report_status(f'Opted out via: {results["opt_out_method"]}', 7)
    elif results["opt_out_clicked"] == "yes":
        results["notes"].append(
            "Opt-out was clicked but banner may still be visible — unverified."
        )
        report_status("Opt-out clicked but banner still visible", 7)
    else:
        results["notes"].append("No cookie consent banner found.")
        report_status("No cookie consent banner found", 7)

    # ── Step 7: Wait after opt-out ──────────────────────────────────
    # Give the site time to actually disable trackers.
    if results["opt_out_clicked"] == "yes":
        print(f"[*] Waiting {POST_OPTOUT_WAIT}s for site to adjust "
              "after opt-out...")
        report_status(f"Waiting {POST_OPTOUT_WAIT}s for site to adjust...", 8)
        page.wait_for_timeout(POST_OPTOUT_WAIT * 1000)

    # ── Step 8: Simulate real shopping behaviour ────────────────────
    # Trackers often only fire when the user browses products, not
    # just on the homepage.  We navigate to the shop page, click a
    # product, and capture all requests made during that flow.

    # After opt-out, verify we're still on the target domain.
    # Some consent buttons redirect the browser away.
    current_url_check = page.url
    target_base = domain.replace("www.", "")
    if target_base not in current_url_check:
        print(f"[!] Opt-out navigated away to {current_url_check} — returning to {url}")
        results["notes"].append(f"Opt-out redirected to {current_url_check}; returned to target.")
        try:
            page.goto(url, timeout=PAGE_LOAD_TIMEOUT, wait_until="networkidle")
            page.wait_for_timeout(3000)
        except PlaywrightTimeout:
            pass
        except Exception as e:
            print(f"[!] Failed to navigate back: {e}")

    # Clear old requests so we only capture post-opt-out activity.
    captured_requests.clear()
    request_details.clear()

    # 8a. Navigate to the shop / all-products page.
    print("[*] Looking for a Shop / All Products link...")
    report_status("Looking for Shop page...", 9)
    shop_clicked = navigate_to_shop(page)

    if shop_clicked:
        print(f'[*] Navigated to shop page via: "{shop_clicked}"')
        report_status(f"Navigated to shop page", 10)
        # Wait for the shop page to fully load.
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except PlaywrightTimeout:
            pass  # some shop pages never fully idle
        page.wait_for_timeout(3000)

        # 8b. Clear again — we only care about the product click.
        captured_requests.clear()
        request_details.clear()

        # 8c. Click the first product on the shop page.
        print("[*] Looking for a product to click...")
        report_status("Browsing products...", 11)
        product_clicked = click_first_product(page)

        if product_clicked:
            print("[*] Clicked on a product — monitoring network requests...")
            report_status("Clicked product — monitoring network requests...", 12)
            # Wait for the product page to fully load.
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except PlaywrightTimeout:
                pass
            page.wait_for_timeout(5000)

            # Scroll down the product page to trigger lazy trackers.
            try:
                page.mouse.move(640, 450)
                for _ in range(3):
                    page.mouse.wheel(0, 400)
                    page.wait_for_timeout(1500)
            except Exception:
                pass
            results["notes"].append("Browsed to shop page and clicked a product.")
        else:
            print("[!] Could not find a product to click on the shop page.")
            results["notes"].append("Found shop page but could not click a product.")
            # Fall back: monitor the shop page itself for a while.
            page.wait_for_timeout(POST_OPTOUT_MONITOR * 1000)
    else:
        print("[!] Could not find a Shop / All Products link.")
        report_status("No shop page found — trying products on current page", 10)

        # Try clicking a product directly on the homepage.
        captured_requests.clear()
        request_details.clear()
        report_status("Looking for products on current page...", 11)
        product_clicked = click_first_product(page)

        if product_clicked:
            print("[*] Clicked on a product from homepage — monitoring...")
            report_status("Clicked product — monitoring network requests...", 12)
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except PlaywrightTimeout:
                pass
            page.wait_for_timeout(5000)

            try:
                page.mouse.move(640, 450)
                for _ in range(3):
                    page.mouse.wheel(0, 400)
                    page.wait_for_timeout(1500)
            except Exception:
                pass
            results["notes"].append("Clicked a product directly from homepage.")
        else:
            results["notes"].append("Could not find shop link or products; monitored homepage instead.")
            # Fall back: scroll and interact with the homepage.
            try:
                page.mouse.move(640, 450)
                for _ in range(3):
                    page.mouse.wheel(0, 400)
                    page.wait_for_timeout(1500)
            except Exception:
                pass
            page.wait_for_timeout(POST_OPTOUT_MONITOR * 1000)

    # ── Step 9: Check for continued tracking ────────────────────────
    # Now look at everything the browser sent during the shopping flow.
    results["trackers_after"] = collect_tracker_hits(captured_requests)

    # Group ALL post-opt-out requests by domain for the detailed report.
    request_domains = group_requests_by_domain(captured_requests)

    # Flag every request domain that matches a tracker.
    flagged_domains = {}
    for req_domain, count in request_domains.items():
        match = is_tracker_request(req_domain)
        if match:
            flagged_domains[req_domain] = {"count": count, "matched_rule": match}

    # Re-check cookies — were new third-party cookies set after opt-out?
    all_cookies_after = context.cookies()
    results["cookies_after_details"] = all_cookies_after
    tp_cookies_after = find_third_party_cookies(all_cookies_after, domain)

    # Compute new cookies set AFTER opt-out (full objects, not just domains).
    before_keys = {(c["name"], c["domain"]) for c in all_cookies}
    results["new_cookies_details"] = [
        c for c in all_cookies_after
        if (c["name"], c["domain"]) not in before_keys
    ]

    # New third-party cookies set AFTER the opt-out.
    new_tp_cookie_domains = sorted(
        {c["domain"] for c in tp_cookies_after}
        - {c["domain"] for c in tp_cookies_before}
    )

    # ── Print detailed network report ──────────────────────────────
    print(f"\n[*] === POST-OPT-OUT NETWORK REPORT ===")
    print(f"[*] Total requests captured: {len(captured_requests)}")
    print(f"[*] Unique domains contacted: {len(request_domains)}")
    report_status("Analyzing post-opt-out network traffic...", 13)

    if flagged_domains:
        print(f"\n[!] FLAGGED TRACKER DOMAINS ({len(flagged_domains)}):")
        for fd, info in sorted(flagged_domains.items()):
            print(f"      - {fd}  ({info['count']} requests)  "
                  f"[matched: {info['matched_rule']}]")
        report_status(f"Found {len(flagged_domains)} flagged tracker domains", 14)
    else:
        print("[*] No known tracker domains found in post-opt-out requests.")
        report_status("No tracker domains found after opt-out", 14)

    # Flag as a violation ONLY if opt-out was verified AND trackers still present.
    # If opt-out was not verified, mark as inconclusive regardless.
    if results["trackers_after"]:
        if results["opt_out_verified"] == "yes":
            results["still_tracking"] = "yes"
        else:
            results["still_tracking"] = "inconclusive"

    if new_tp_cookie_domains:
        # Check if any new third-party cookie domains match known trackers.
        tracker_cookie_domains = [
            d for d in new_tp_cookie_domains if is_tracker_request(d.lstrip("."))
        ]
        if tracker_cookie_domains:
            if results["opt_out_verified"] == "yes":
                results["still_tracking"] = "yes"
            elif results["still_tracking"] != "yes":
                results["still_tracking"] = "inconclusive"
            print(f"\n[!] NEW tracker cookies set after opt-out:")
            for d in tracker_cookie_domains:
                print(f"      - {d}")
            results["notes"].append(
                f"New tracker cookies after opt-out: "
                f"{json.dumps(tracker_cookie_domains)}"
            )

        # Log all new third-party cookies (even non-tracker ones) as notes.
        non_tracker = [d for d in new_tp_cookie_domains if d not in tracker_cookie_domains]
        if non_tracker:
            print(f"\n[*] Other new third-party cookies (not flagged):")
            for d in non_tracker:
                print(f"      - {d}")
            results["notes"].append(
                f"Other new third-party cookies: {json.dumps(non_tracker)}"
            )

    # Store the full domain breakdown in results for the summary.
    results["flagged_domains"] = flagged_domains
    results["all_request_domains"] = request_domains

    # ── Step 10: Verify we're still on target domain ────────────────
    # The browser may have navigated away during opt-out or product
    # browsing (e.g. redirected to Google or another site).
    current_url = page.url
    target_base = domain.replace("www.", "")
    if target_base not in current_url:
        print(f"[!] Browser navigated away to {current_url} — returning to {url}")
        results["notes"].append(f"Browser navigated away to {current_url}; returned to target.")
        try:
            page.goto(url, timeout=PAGE_LOAD_TIMEOUT, wait_until="networkidle")
            page.wait_for_timeout(3000)
        except PlaywrightTimeout:
            pass
        except Exception as e:
            print(f"[!] Failed to navigate back: {e}")

    # Take "after" screenshot.
    after_path = os.path.join(SCREENSHOTS_DIR, f"{safe_domain}_after.png")
    try:
        page.screenshot(path=after_path, full_page=True)
        results["screenshot_after"] = after_path
        print(f"[*] 'After' screenshot saved: {after_path}")
        report_status("After screenshot captured", 15)
    except Exception as e:
        print(f"[!] Screenshot failed: {e}")

    # Viewport-only screenshot for DevTools evidence composite.
    viewport_path = os.path.join(SCREENSHOTS_DIR, f"{safe_domain}_viewport.png")
    try:
        page.screenshot(path=viewport_path, full_page=False)
        results["screenshot_viewport"] = viewport_path
        print(f"[*] Viewport screenshot saved: {viewport_path}")
    except Exception as e:
        print(f"[!] Viewport screenshot failed: {e}")

    # ── Step 11: Save to database ───────────────────────────────────
    screenshot_paths = json.dumps({
        "before": results["screenshot_before"],
        "after": results["screenshot_after"],
        "viewport": results.get("screenshot_viewport"),
        "optout": results.get("screenshot_optout"),
    })

    row_id = database.save_scan_result(
        url=url,
        opt_out_found=results["opt_out_found"],
        opt_out_clicked=results["opt_out_clicked"],
        trackers_before_optout=json.dumps(results["trackers_before"]),
        trackers_after_optout=json.dumps(results["trackers_after"]),
        still_tracking=results["still_tracking"],
        screenshot_path=screenshot_paths,
        evidence_notes="; ".join(results["notes"]) if results["notes"] else None,
    )
    print(f"[*] Results saved to database (row id={row_id}).")
    report_status("Results saved to database", 16)

    # Store detailed request metadata for evidence package.
    results["request_details"] = list(request_details)

    # ── Clean up ────────────────────────────────────────────────────
    context.close()

    # ── Step 12: Print summary ──────────────────────────────────────
    print_summary(results)
    report_status("Scan complete", 17)

    return results


def print_summary(results):
    """Print a human-readable summary of a single scan."""
    print(f"\n{'─' * 60}")
    print(f"  SUMMARY FOR: {results['url']}")
    print(f"{'─' * 60}")
    print(f"  Opt-out banner found : {results['opt_out_found']}")
    print(f"  Opt-out clicked      : {results['opt_out_clicked']}")
    print(f"  Trackers before      : {len(results['trackers_before'])} "
          f"{results['trackers_before']}")
    print(f"  Trackers after       : {len(results['trackers_after'])} "
          f"{results['trackers_after']}")

    # Show every flagged domain with request counts.
    flagged = results.get("flagged_domains", {})
    if flagged:
        print(f"\n  FLAGGED DOMAINS (post-opt-out browsing):")
        for fd, info in sorted(flagged.items()):
            print(f"    {fd:45s}  {info['count']:>3} reqs  "
                  f"[{info['matched_rule']}]")

    if results["still_tracking"] == "yes":
        print(f"\n  *** STILL TRACKING AFTER OPT-OUT ***")
    elif results["still_tracking"] == "inconclusive":
        print(f"\n  *** INCONCLUSIVE — Opt-out could not be verified ***")
    else:
        print(f"\n  Tracking stopped after opt-out: OK")

    if results["notes"]:
        print(f"  Notes: {'; '.join(results['notes'])}")
    print(f"{'─' * 60}\n")


# ────────────────────────────────────────────────────────────────────
# URL LOADING
# ────────────────────────────────────────────────────────────────────

def load_urls_from_file(filepath):
    """
    Read URLs from a text file (one URL per line).

    Blank lines and lines starting with # are ignored.
    """
    urls = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def normalize_url(url):
    """Make sure the URL starts with http:// or https://."""
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


# ────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ────────────────────────────────────────────────────────────────────

def main():
    # ── Parse command-line arguments ────────────────────────────────
    parser = argparse.ArgumentParser(
        description="Privacy Compliance Scanner — checks whether websites "
                    "respect cookie opt-out choices."
    )
    parser.add_argument(
        "urls",
        nargs="*",
        help="One or more URLs to scan.",
    )
    parser.add_argument(
        "--file", "-f",
        default=None,
        help="Path to a text file containing URLs (one per line). "
             "Defaults to 'urls.txt' if no URLs are provided.",
    )
    args = parser.parse_args()

    # Build the list of URLs to scan.
    urls = []
    if args.urls:
        urls = args.urls
    elif args.file:
        urls = load_urls_from_file(args.file)
    elif os.path.exists("urls.txt"):
        print("[*] No URLs provided — reading from urls.txt")
        urls = load_urls_from_file("urls.txt")

    if not urls:
        print("[!] No URLs to scan.")
        print("    Usage:  python scanner.py https://example.com")
        print("    Or:     python scanner.py --file urls.txt")
        sys.exit(1)

    # Normalise all URLs (add https:// if missing).
    urls = [normalize_url(u) for u in urls]

    print(f"\n[*] Privacy Compliance Scanner")
    print(f"[*] Scanning {len(urls)} URL(s)...\n")

    # ── Initialise the database ─────────────────────────────────────
    database.init_db()

    # ── Launch the browser ──────────────────────────────────────────
    # We use Playwright's sync API with headless Chromium.
    with sync_playwright() as pw:
        print("[*] Launching headless Chromium browser...")
        browser = pw.chromium.launch(headless=True)

        all_results = []

        for i, url in enumerate(urls, start=1):
            print(f"\n[{i}/{len(urls)}] Starting scan...")

            try:
                result = scan_url(browser, url)
                all_results.append(result)
            except Exception as e:
                # ── Error handling ──────────────────────────────────
                # If anything goes wrong with one site, log it and
                # move on.  One bad site should never stop the whole
                # scan.
                print(f"\n[!!!] SCAN FAILED for {url}: {e}")
                print("[*] Moving on to next URL...\n")
                all_results.append({
                    "url": url,
                    "error": str(e),
                    "still_tracking": "unknown",
                })
                # Save the error to the database too.
                database.save_scan_result(
                    url=url,
                    evidence_notes=f"Scan failed with error: {e}",
                )

        browser.close()

    # ── Final report ────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  SCAN COMPLETE — {len(all_results)} site(s) scanned")
    print(f"{'=' * 60}")

    violations = [r for r in all_results if r.get("still_tracking") == "yes"]
    clean = [r for r in all_results if r.get("still_tracking") == "no"]
    inconclusive = [r for r in all_results if r.get("still_tracking") == "inconclusive"]
    errors = [r for r in all_results if r.get("still_tracking") == "unknown"]

    print(f"  Violations (still tracking after opt-out): {len(violations)}")
    for v in violations:
        print(f"    - {v['url']}")

    print(f"  Clean (stopped tracking after opt-out)   : {len(clean)}")
    for c in clean:
        print(f"    - {c['url']}")

    if inconclusive:
        print(f"  Inconclusive (opt-out not verified)      : {len(inconclusive)}")
        for i in inconclusive:
            print(f"    - {i['url']}")

    if errors:
        print(f"  Errors (scan failed)                     : {len(errors)}")
        for e in errors:
            print(f"    - {e['url']}: {e.get('error', 'unknown')}")

    print(f"\nResults saved to: {database.DATABASE_NAME}")
    print(f"Screenshots in:   {SCREENSHOTS_DIR}/")


if __name__ == "__main__":
    main()
