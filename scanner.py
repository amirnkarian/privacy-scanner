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

# ────────────────────────────────────────────────────────────────────
# TIKTOK-SPECIFIC TRACKER DOMAINS
#
# Only TikTok tracking determines FAIL/PASS.  All other trackers are
# still detected and logged for evidence, but do not trigger violations.
# ────────────────────────────────────────────────────────────────────

TIKTOK_TRACKER_DOMAINS = [
    "analytics.tiktok.com",
    "business-api.tiktok.com",
]

TIKTOK_TRACKER_URL_PATTERNS = [
    "tiktok.com/analytics",
    "www.tiktok.com/api",
]

TIKTOK_COOKIES = ["_ttp", "_tt_enable_cookie"]

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


def is_tiktok_request(request_url):
    """Check if a network request URL matches a known TikTok tracker."""
    for domain in TIKTOK_TRACKER_DOMAINS:
        if domain in request_url:
            return domain
    for pattern in TIKTOK_TRACKER_URL_PATTERNS:
        if pattern in request_url:
            return pattern
    return None


def collect_tiktok_hits(captured_requests):
    """Return sorted list of unique TikTok tracker domains contacted."""
    found = set()
    for url in captured_requests:
        match = is_tiktok_request(url)
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

# Selectors for known cookie consent framework banners/modals.
_BANNER_SELECTORS = [
    '#onetrust-banner-sdk',
    '#onetrust-consent-sdk',
    '#CybotCookiebotDialog',
    '.truste-consent-track',
    '#truste-consent-track',
    '.osano-cm-window',
    '[class*="cookie-banner"]',
    '[class*="consent-banner"]',
    '[id*="cookie-banner"]',
    '[id*="consent-banner"]',
    '[class*="cookie-modal"]',
    '[class*="consent-modal"]',
    '[class*="cookie-notice"]',
    '[class*="consent-notice"]',
    '.truste_overlay',
    '.truste_box_overlay',
    '.truste_cm_outerdiv',
]

# Footer link texts for finding privacy/cookie preference links.
_FOOTER_PRIVACY_TEXTS = [
    "Your Privacy Choices",
    "Cookie Preferences",
    "Cookie Settings",
    "Cookie Management",
    "Manage Cookies",
    "Privacy Settings",
    "Do Not Sell My Personal Information",
    "Do Not Sell or Share My Personal Information",
    "Do Not Sell or Share",
    "Do Not Sell",
    "Ad Preferences",
    "Privacy Center",
    "Cookie Policy",
    "Manage Your Cookie Preferences",
]

# Categories to DISABLE when toggling preferences.
_DISABLE_CATEGORIES = [
    "analytics", "advertising", "marketing", "targeting",
    "personalization", "performance", "social media",
    "targeted advertising", "functional", "statistics",
    "preference", "sale of personal data",
]

# Categories to LEAVE ENABLED (essential/required).
_KEEP_ENABLED_CATEGORIES = [
    "essential", "strictly necessary", "required", "necessary",
]

# Save/confirm button texts for preference panels.
_SAVE_TEXTS = [
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
    "Apply",
    "Submit",
    "Save & Close",
    "Save and close",
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


# Selectors for preference panels/modals (opened by footer links or settings buttons).
_PREFERENCE_PANEL_SELECTORS = [
    '#onetrust-pc-sdk',
    '.ot-preference-center',
    '#CybotCookiebotDialogDetail',
    '.truste_overlay',
    '.truste_box_overlay',
    '.truste_cm_outerdiv',
    'iframe[src*="consent-pref.trustarc"]',
    '[class*="cookie-settings"]',
    '[class*="cookie-preferences"]',
    '[class*="privacy-center"]',
    '[id*="cookie-settings"]',
    '[id*="privacy-preferences"]',
    '[role="dialog"][aria-label*="cookie" i]',
    '[role="dialog"][aria-label*="privacy" i]',
    '[role="dialog"][aria-label*="consent" i]',
]


def _is_preference_panel_dismissed(page):
    """Check if a cookie preference panel/modal has been dismissed."""
    for selector in _PREFERENCE_PANEL_SELECTORS:
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


def _take_optout_screenshot(page, safe_domain, suffix="optout"):
    """Take a screenshot during opt-out for verification."""
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    path = os.path.join(SCREENSHOTS_DIR, f"{safe_domain}_{suffix}.png")
    try:
        page.screenshot(path=path, full_page=False)
        return path
    except Exception:
        return None


def _scroll_to_bottom(page):
    """Scroll to the very bottom of the page to reveal lazy-loaded footer content."""
    try:
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        page.wait_for_timeout(1500)
        # Scroll again in case more content loaded
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        page.wait_for_timeout(1000)
    except Exception:
        pass


def _is_essential_category(text):
    """Check if a toggle label belongs to an essential/required category."""
    lower = text.lower().strip()
    for keep in _KEEP_ENABLED_CATEGORIES:
        if keep in lower:
            return True
    return False


def _disable_non_essential_toggles(page):
    """
    Find and disable all non-essential cookie toggles in a preference panel.
    Returns the number of toggles flipped.
    """
    toggles_flipped = 0

    # Strategy A: Find labeled toggle groups and disable non-essential ones.
    # Many consent managers wrap toggles in containers with category labels.
    toggle_container_selectors = [
        # OneTrust
        '.ot-sdk-row',
        '.ot-cat-item',
        # Generic
        '.cookie-category',
        '.consent-category',
        '[class*="preference-group"]',
        '[class*="cookie-group"]',
        '[class*="toggle-group"]',
    ]

    for container_sel in toggle_container_selectors:
        try:
            containers = page.locator(container_sel)
            count = containers.count()
            for i in range(count):
                container = containers.nth(i)
                try:
                    label_text = container.inner_text(timeout=500)
                    if _is_essential_category(label_text):
                        continue
                    # Look for active toggles inside this container
                    for toggle_sel in [
                        'input[type="checkbox"]:checked',
                        '[aria-checked="true"]',
                        '.ot-switch input:checked',
                    ]:
                        try:
                            toggle = container.locator(toggle_sel).first
                            if toggle.is_visible(timeout=300):
                                toggle.click(timeout=1000)
                                toggles_flipped += 1
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            continue

    # Strategy B: If no containers found, try all toggles globally
    # but skip those near "essential"/"necessary" labels.
    if toggles_flipped == 0:
        global_toggle_selectors = [
            'input[type="checkbox"]:checked',
            '[aria-checked="true"]',
            '.ot-switch input:checked',
            'button[role="switch"][aria-checked="true"]',
            '.toggle-switch.active',
            '[class*="toggle"][class*="on"]',
            '[class*="switch"][class*="active"]',
        ]
        for sel in global_toggle_selectors:
            try:
                toggles = page.locator(sel)
                count = toggles.count()
                for i in range(count):
                    try:
                        toggle = toggles.nth(i)
                        if not toggle.is_visible(timeout=300):
                            continue
                        # Check nearby text for essential categories
                        try:
                            parent_text = toggle.locator("xpath=ancestor::*[position()<=3]").last.inner_text(timeout=300)
                            if _is_essential_category(parent_text):
                                continue
                        except Exception:
                            pass
                        toggle.click(timeout=1000)
                        toggles_flipped += 1
                    except Exception:
                        continue
            except Exception:
                continue

    return toggles_flipped


# ── Strategy 1: Popup/Banner Detection ────────────────────────────

def _try_banner_optout(page):
    """
    Strategy 1: Find and interact with cookie consent banners/popups.
    Tries framework-specific selectors first, then generic text buttons,
    then manage-preferences flow.
    Returns dict with keys: strategy, clicked, element.
    """
    attempt = {"strategy": "banner_popup", "clicked": False, "element": None}

    # ── OneTrust ──────────────────────────────────────────────
    try:
        banner = page.query_selector('#onetrust-banner-sdk')
        if banner and banner.is_visible():
            if _safe_click(page, '#onetrust-reject-all-handler'):
                attempt["clicked"] = True
                attempt["element"] = "OneTrust: Reject All"
                return attempt
            if _safe_click(page, '#onetrust-pc-btn-handler'):
                page.wait_for_timeout(2000)
                if _safe_click(page, '.ot-pc-refuse-all-handler'):
                    attempt["clicked"] = True
                    attempt["element"] = "OneTrust: Preference Center → Reject All"
                    return attempt
                # Disable toggles, then save
                flipped = _disable_non_essential_toggles(page)
                save_clicked = try_click_button(page, _SAVE_TEXTS)
                if save_clicked:
                    attempt["clicked"] = True
                    attempt["element"] = f"OneTrust: Preference Center → {save_clicked}"
                    if flipped > 0:
                        attempt["element"] += f" (disabled {flipped} toggles)"
                    return attempt
                if _safe_click(page, 'button.save-preference-btn-handler'):
                    attempt["clicked"] = True
                    attempt["element"] = "OneTrust: Preference Center → Save Preferences"
                    if flipped > 0:
                        attempt["element"] += f" (disabled {flipped} toggles)"
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
                    clicked_save = try_click_button(page, _SAVE_TEXTS)
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

    # ── Generic text-based buttons ────────────────────────────
    clicked = try_click_button(page, PRIMARY_OPTOUT_TEXTS)
    if clicked:
        attempt["clicked"] = True
        attempt["element"] = f"Banner button: {clicked}"
        return attempt

    # ── Generic manage-preferences flow ───────────────────────
    manage_clicked = try_click_button(page, MANAGE_PREFS_TEXTS)
    if manage_clicked:
        print(f'[*] Clicked preferences button: "{manage_clicked}"')
        page.wait_for_timeout(2000)

        # Try reject-all first inside the panel
        reject = try_click_button(page, PRIMARY_OPTOUT_TEXTS)
        if reject:
            attempt["clicked"] = True
            attempt["element"] = f"Banner ({manage_clicked}) → {reject}"
            return attempt

        # Disable toggles
        flipped = _disable_non_essential_toggles(page)

        # Save
        save_clicked = try_click_button(page, _SAVE_TEXTS)
        if save_clicked:
            attempt["clicked"] = True
            attempt["element"] = f"Banner ({manage_clicked}) → {save_clicked}"
            if flipped > 0:
                attempt["element"] += f" (disabled {flipped} toggles)"
            return attempt

    return attempt


# ── Strategy 2: Footer Privacy Links ─────────────────────────────

def _dismiss_popups(page):
    """Dismiss common marketing popups/overlays that block footer interactions."""
    popup_close_selectors = [
        '#attentive_overlay .attentive-close',
        '#attentive_overlay [aria-label="Close"]',
        '#attentive_overlay button',
        '.attentive-dismiss',
        '[id*="attentive"] [class*="close"]',
        '.popup-close',
        '.modal-close',
        '[class*="popup"] [class*="close"]',
        '[class*="overlay"] [class*="close"]',
        '[class*="newsletter"] [class*="close"]',
        '[class*="signup"] [class*="close"]',
        'button[aria-label="Close"]',
        'button[aria-label="close"]',
        '[class*="email-popup"] [class*="close"]',
    ]
    for sel in popup_close_selectors:
        try:
            locator = page.locator(sel).first
            if locator.is_visible(timeout=300):
                locator.click(timeout=2000)
                page.wait_for_timeout(500)
                return True
        except Exception:
            continue

    # Try removing attentive overlay via JS as a fallback
    try:
        page.evaluate("""
            const overlay = document.getElementById('attentive_overlay');
            if (overlay) overlay.remove();
            // Also try removing any fixed-position overlays
            document.querySelectorAll('[style*="position: fixed"]').forEach(el => {
                if (el.offsetHeight > 300 && el.offsetWidth > 300) {
                    const z = parseInt(window.getComputedStyle(el).zIndex) || 0;
                    if (z > 1000) el.remove();
                }
            });
        """)
        page.wait_for_timeout(500)
    except Exception:
        pass
    return False


def _try_footer_optout(page, original_url):
    """
    Strategy 2: Scroll to footer, find privacy/cookie links, click them,
    and handle whatever opens (modal, preference panel, or new page).
    Returns dict with keys: strategy, clicked, element.
    """
    attempt = {"strategy": "footer_link", "clicked": False, "element": None}

    # Dismiss any marketing popups that may block footer clicks
    _dismiss_popups(page)

    # Scroll to the very bottom to reveal lazy-loaded footer content.
    print("[*] Scrolling to bottom of page to find footer links...")
    _scroll_to_bottom(page)

    # Dismiss popups again after scrolling (some appear on scroll)
    _dismiss_popups(page)

    # Record the current URL to detect page navigations
    url_before = page.url

    for text in _FOOTER_PRIVACY_TEXTS:
        try:
            # Search in footer first, then body, then any element
            for selector in [
                f'footer a:has-text("{text}")',
                f'footer button:has-text("{text}")',
                f'footer span:has-text("{text}")',
                f'footer div:has-text("{text}")',
                f'a:has-text("{text}")',
                f'button:has-text("{text}")',
                f'[role="link"]:has-text("{text}")',
                f'[role="button"]:has-text("{text}")',
            ]:
                try:
                    locator = page.locator(selector).first
                    if not locator.is_visible(timeout=500):
                        continue
                except Exception:
                    continue

                # Found a visible link — click it
                try:
                    locator.click(timeout=5000)
                except Exception:
                    # If regular click fails (e.g. overlay), try force click
                    try:
                        locator.click(timeout=3000, force=True)
                    except Exception:
                        continue

                print(f'[*] Clicked footer privacy link: "{text}"')
                page.wait_for_timeout(3000)

                # Check if we navigated to a new page (like AG1's privacy center)
                url_after = page.url
                navigated_away = url_after != url_before

                if navigated_away:
                    print(f"[*] Navigated to privacy center: {url_after}")
                    # Wait for the page to load
                    try:
                        page.wait_for_load_state("networkidle", timeout=15000)
                    except PlaywrightTimeout:
                        pass
                    page.wait_for_timeout(2000)

                    # On the privacy center page, look for a "Manage Cookie Preferences" link
                    manage_texts = [
                        "Manage Your Cookie Preferences",
                        "Manage Cookie Preferences",
                        "Cookie Preferences",
                        "Cookie Settings",
                        "Manage Cookies",
                        "Manage Preferences",
                    ]
                    for mt in manage_texts:
                        sub_clicked = try_click_button(page, [mt])
                        if sub_clicked:
                            print(f'[*] Clicked: "{sub_clicked}" on privacy center page')
                            page.wait_for_timeout(3000)
                            break

                # Now try to interact with whatever appeared (modal, panel, or page)
                result = _interact_with_preference_panel(page)
                if result:
                    attempt["clicked"] = True
                    attempt["verified"] = True
                    attempt["element"] = f"Footer ({text}) → {result}"
                    return attempt

                # If nothing worked, try going back if we navigated
                if navigated_away:
                    try:
                        page.goto(original_url, timeout=PAGE_LOAD_TIMEOUT, wait_until="networkidle")
                        page.wait_for_timeout(2000)
                    except Exception:
                        pass

                # This link didn't work — break inner selector loop, try next text
                break
        except Exception:
            continue

    # Also try the CCPA toggle icon (a blue toggle/slider icon)
    try:
        for icon_sel in [
            'a[href*="privacy"]',
            '[class*="ccpa"]',
            '[class*="privacy-choices"]',
            '[id*="ccpa"]',
            'img[alt*="Privacy"]',
            'img[alt*="CCPA"]',
            'img[alt*="privacy choices"]',
        ]:
            locator = page.locator(f'footer {icon_sel}').first
            if locator.is_visible(timeout=500):
                locator.click(timeout=3000)
                print(f"[*] Clicked CCPA/privacy icon in footer")
                page.wait_for_timeout(3000)
                result = _interact_with_preference_panel(page)
                if result:
                    attempt["clicked"] = True
                    attempt["verified"] = True
                    attempt["element"] = f"Footer CCPA icon → {result}"
                    return attempt
                break
    except Exception:
        pass

    return attempt


def _try_trustarc_iframe(page):
    """
    Handle TrustArc consent managers that use an iframe.
    Finds the iframe, clicks 'No' on advertising, then 'Save'.
    Returns a description string if successful, or None.
    """
    # Find the TrustArc iframe
    frame = None
    try:
        frame = page.frame(url="*consent-pref.trustarc.com*")
    except Exception:
        pass

    if not frame:
        try:
            iframe_el = page.query_selector('iframe[title*="TrustArc"]')
            if not iframe_el:
                iframe_el = page.query_selector('iframe[src*="trustarc"]')
            if not iframe_el:
                iframe_el = page.query_selector('iframe[src*="consent-pref"]')
            if iframe_el:
                frame = iframe_el.content_frame()
        except Exception:
            pass

    if not frame:
        return None

    print("[*] Found TrustArc iframe — interacting with consent preferences...")

    toggled = 0
    try:
        # Click all "No" buttons that aren't already active (opt out of non-essential)
        # TrustArc uses spans with class "on" for "No" and "off" for "Yes"
        # The active one has class "active"
        no_buttons = frame.locator('span.gwt-InlineHTML.on:not(.active)')
        count = no_buttons.count()
        for i in range(count):
            try:
                btn = no_buttons.nth(i)
                if btn.is_visible(timeout=500):
                    btn.click(timeout=2000)
                    toggled += 1
                    page.wait_for_timeout(500)
            except Exception:
                continue
    except Exception:
        pass

    # Click Save
    try:
        save_btn = frame.locator('a.submit, button.submit, a:has-text("SAVE"), a:has-text("Save")')
        if save_btn.first.is_visible(timeout=1000):
            save_btn.first.click(timeout=3000)
            page.wait_for_timeout(2000)
            # Close the TrustArc overlay after saving
            try:
                close_btn = page.locator('#trustarc-internal-close-button, .truste-close-button')
                if close_btn.first.is_visible(timeout=1000):
                    close_btn.first.click(timeout=2000)
                    page.wait_for_timeout(1000)
            except Exception:
                # Try removing the overlay via JS
                try:
                    page.evaluate("""
                        document.querySelector('.truste_overlay')?.remove();
                        document.querySelector('.truste_cm_outerdiv')?.remove();
                        document.querySelector('.truste_box_overlay')?.remove();
                    """)
                except Exception:
                    pass
            desc = "TrustArc iframe: Save"
            if toggled > 0:
                desc = f"TrustArc iframe: toggled {toggled} to No → Save"
            return desc
    except Exception:
        pass

    # If we toggled but couldn't save, still report
    if toggled > 0:
        return f"TrustArc iframe: toggled {toggled} to No (save not found)"

    return None


def _interact_with_preference_panel(page):
    """
    Given that a preference panel/modal/page is now visible,
    try to opt out by: (1) clicking Reject All, (2) TrustArc iframe,
    (3) disabling toggles + save.
    Returns a description string if successful, or None.
    """
    # Try framework-specific first
    # OneTrust preference center
    if _safe_click(page, '#onetrust-reject-all-handler'):
        return "OneTrust Reject All"
    if _safe_click(page, '.ot-pc-refuse-all-handler'):
        return "OneTrust Preference Center Reject All"

    # CookieBot
    if _safe_click(page, '#CybotCookiebotDialogBodyButtonDecline'):
        return "CookieBot Decline"

    # TrustArc — try direct buttons first
    if _safe_click(page, '.truste-consent-required'):
        return "TrustArc Required Only"

    # TrustArc — iframe-based consent manager
    trustarc_result = _try_trustarc_iframe(page)
    if trustarc_result:
        return trustarc_result

    # Generic reject/decline buttons
    reject = try_click_button(page, PRIMARY_OPTOUT_TEXTS)
    if reject:
        return reject

    # Try Reject All / Refuse All in save texts
    for text in ["Reject All", "Reject all", "Refuse All", "Refuse all",
                 "Reject Targeting and Marketing"]:
        clicked = try_click_button(page, [text])
        if clicked:
            return clicked

    # Disable toggles + save
    flipped = _disable_non_essential_toggles(page)
    save_clicked = try_click_button(page, _SAVE_TEXTS)
    if save_clicked:
        desc = save_clicked
        if flipped > 0:
            desc += f" (disabled {flipped} toggles)"
        return desc

    # Try save button by selector
    if _safe_click(page, 'button.save-preference-btn-handler'):
        desc = "Save Preferences"
        if flipped > 0:
            desc += f" (disabled {flipped} toggles)"
        return desc

    return None


# ── Strategy 3: JavaScript Consent API Calls ─────────────────────

def _try_js_consent_api(page):
    """
    Strategy 3: Directly trigger consent manager opt-out via JavaScript.
    Returns dict with keys: strategy, clicked, element.
    """
    attempt = {"strategy": "js_consent_api", "clicked": False, "element": None}

    # ── OneTrust: RejectAll() ─────────────────────────────────
    try:
        has_onetrust = page.evaluate("typeof OneTrust !== 'undefined'")
        if has_onetrust:
            page.evaluate("OneTrust.RejectAll()")
            page.wait_for_timeout(1500)
            attempt["clicked"] = True
            attempt["verified"] = True
            attempt["element"] = "OneTrust.RejectAll() via JavaScript"
            return attempt
    except Exception:
        pass

    # ── OneTrust: reject button via selector ──────────────────
    try:
        if _safe_click(page, '#onetrust-reject-all-handler'):
            attempt["clicked"] = True
            attempt["verified"] = True
            attempt["element"] = "OneTrust: #onetrust-reject-all-handler"
            return attempt
    except Exception:
        pass

    # ── CookieBot: withdraw() ─────────────────────────────────
    try:
        has_cookiebot = page.evaluate("typeof Cookiebot !== 'undefined'")
        if has_cookiebot:
            page.evaluate("Cookiebot.withdraw()")
            page.wait_for_timeout(1500)
            attempt["clicked"] = True
            attempt["verified"] = True
            attempt["element"] = "Cookiebot.withdraw() via JavaScript"
            return attempt
    except Exception:
        pass

    # ── CookieBot: decline button via selector ────────────────
    try:
        if _safe_click(page, '#CybotCookiebotDialogBodyButtonDecline'):
            attempt["clicked"] = True
            attempt["verified"] = True
            attempt["element"] = "CookieBot: #CybotCookiebotDialogBodyButtonDecline"
            return attempt
    except Exception:
        pass

    # ── TrustArc: required-only button ────────────────────────
    try:
        if _safe_click(page, '.truste-consent-required'):
            attempt["clicked"] = True
            attempt["verified"] = True
            attempt["element"] = "TrustArc: .truste-consent-required"
            return attempt
    except Exception:
        pass

    # ── Generic: try triggering via common JS globals ─────────
    js_attempts = [
        ("typeof __tcfapi !== 'undefined'",
         "__tcfapi('setConsent', 2, function(){}, {vendor: {consents: {}}, purpose: {consents: {}}})",
         "TCF API: setConsent via __tcfapi"),
    ]
    for check_js, exec_js, desc in js_attempts:
        try:
            has_api = page.evaluate(check_js)
            if has_api:
                page.evaluate(exec_js)
                page.wait_for_timeout(1500)
                attempt["clicked"] = True
                attempt["verified"] = True
                attempt["element"] = desc
                return attempt
        except Exception:
            continue

    return attempt


# ── Main Opt-Out Orchestrator ─────────────────────────────────────

def attempt_cookie_optout(page, domain, safe_domain=None):
    """
    Multi-strategy cookie opt-out system.

    Tries strategies in order:
      1. Popup/Banner detection (framework-specific + text buttons)
      2. Footer privacy links (scroll, click, handle navigation)
      3. JavaScript consent API calls

    Verifies success by checking if the consent banner is dismissed.

    Returns a dict with:
      - opt_out_found: "yes" | "no"
      - opt_out_clicked: "yes" | "no"
      - opt_out_verified: "yes" | "no"
      - opt_out_method: description of what worked
      - opt_out_attempts: list of attempt dicts
      - screenshots: dict of screenshot paths taken during opt-out
    """
    results = {
        "opt_out_found": "no",
        "opt_out_clicked": "no",
        "opt_out_verified": "no",
        "opt_out_method": None,
        "opt_out_attempts": [],
        "screenshots": {},
    }

    # Take a "before opt-out" screenshot
    if safe_domain:
        before_ss = _take_optout_screenshot(page, safe_domain, "optout_before")
        if before_ss:
            results["screenshots"]["optout_before"] = before_ss

    original_url = page.url

    strategies = [
        ("Popup/Banner", lambda p: _try_banner_optout(p)),
        ("Footer Privacy Links", lambda p: _try_footer_optout(p, original_url)),
        ("JavaScript Consent API", lambda p: _try_js_consent_api(p)),
    ]

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

            # Take screenshot of preference panel state
            if safe_domain:
                panel_ss = _take_optout_screenshot(page, safe_domain, "optout_panel")
                if panel_ss:
                    results["screenshots"]["optout_panel"] = panel_ss

            page.wait_for_timeout(2000)

            # Strategy-specific verification
            strategy_type = attempt.get("strategy", "")
            verified = False

            if strategy_type == "footer_link":
                # Footer strategy: verified if the full interaction completed
                # (panel opened → reject/toggle → save). _interact_with_preference_panel
                # only returns success when all steps complete.
                if attempt.get("verified"):
                    verified = True
                    print(f"[*] Footer opt-out verified — full interaction completed!")

            elif strategy_type == "js_consent_api":
                # JS API: verified if the call executed successfully
                if attempt.get("verified"):
                    verified = True
                    print(f"[*] JS consent API opt-out verified!")

            else:  # banner_popup
                # Banner strategy: check that banner is no longer visible
                if _is_banner_dismissed(page):
                    verified = True
                    print(f"[*] Banner dismissed — opt-out verified!")

            if verified:
                results["opt_out_verified"] = "yes"
                results["opt_out_method"] = attempt.get("element", name)

                # Take "after opt-out" screenshot
                if safe_domain:
                    after_ss = _take_optout_screenshot(page, safe_domain, "optout_after")
                    if after_ss:
                        results["screenshots"]["optout_after"] = after_ss
                break
            else:
                print(f"[!] Opt-out not verified after {name} — trying next strategy...")
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

    # Final screenshot regardless of outcome
    if safe_domain:
        final_ss = _take_optout_screenshot(page, safe_domain, "optout_final")
        if final_ss:
            results["screenshots"]["optout_final"] = final_ss

    return results


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
    "All",
    "Browse All",
    "Browse all",
    "New Arrivals",
    "New arrivals",
    "new arrivals",
    "Shop",
    "Catalog",
    "Store",
    "Browse",
]

# Common shop/collection URL path patterns to try as fallback.
SHOP_URL_PATTERNS = [
    "/collections/all",
    "/collections",
    "/products",
    "/shop",
    "/shop-all",
    "/catalog",
    "/store",
]


def navigate_to_shop(page):
    """
    Try to find and click a link to the shop / all-products page.

    Strategy:
      1. Look for visible shop links in the main nav/header.
      2. If not found, try opening a hamburger/mobile menu first.
      3. If still not found, try navigating directly to common URL patterns.

    Returns the link text or URL pattern that was used, or None.
    """
    # 1. Look for visible shop links in the main navigation.
    for text in SHOP_LINK_TEXTS:
        try:
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

    # 2. Try opening a hamburger / mobile menu and look again.
    hamburger_selectors = [
        'button[aria-label*="menu" i]',
        'button[aria-label*="Menu" i]',
        'button[aria-label*="nav" i]',
        'button[class*="hamburger" i]',
        'button[class*="menu-toggle" i]',
        '[class*="hamburger"]',
        '[class*="menu-toggle"]',
        '.mobile-nav-trigger',
        '#menu-toggle',
        'button.navbar-toggler',
    ]
    menu_opened = False
    for sel in hamburger_selectors:
        try:
            btn = page.locator(sel).first
            if btn.is_visible(timeout=500):
                btn.click(timeout=3000)
                page.wait_for_timeout(1500)
                menu_opened = True
                break
        except Exception:
            continue

    if menu_opened:
        for text in SHOP_LINK_TEXTS:
            try:
                locator = page.locator(f'a:has-text("{text}")').first
                if locator.is_visible(timeout=500):
                    locator.click(timeout=5000)
                    return text
            except Exception:
                continue

    # 3. Fallback: try navigating directly to common URL patterns.
    base_url = page.url.split("?")[0].split("#")[0].rstrip("/")
    # Get the origin (scheme + host).
    parsed = urlparse(page.url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for pattern in SHOP_URL_PATTERNS:
        try:
            target = origin + pattern
            response = page.goto(target, timeout=15000, wait_until="domcontentloaded")
            if response and response.status < 400:
                print(f"[*] Navigated to {target} via URL pattern fallback")
                return pattern
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
    TOTAL_STEPS = 19

    # We'll collect results as we go and return them at the end.
    results = {
        "url": url,
        "opt_out_found": "no",
        "opt_out_clicked": "no",
        "trackers_before": [],
        "trackers_after": [],
        "tiktok_trackers_after": [],
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

    # Intercept navigator.sendBeacon() by wrapping it with a fetch() call
    # that Playwright can fully capture.  The original sendBeacon still fires
    # (so the site behaves normally), but the fetch ensures we log the URL.
    context.add_init_script("""
        (function() {
            const origBeacon = navigator.sendBeacon.bind(navigator);
            navigator.sendBeacon = function(url, data) {
                try { fetch(url, {method:'POST', body: data, keepalive: true}).catch(()=>{}); } catch(e) {}
                return origBeacon(url, data);
            };
        })();
    """)

    print("[*] Network monitoring started (including sendBeacon interception).")
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

    optout_result = attempt_cookie_optout(page, domain, safe_domain=safe_domain)
    results["opt_out_found"] = optout_result["opt_out_found"]
    results["opt_out_clicked"] = optout_result["opt_out_clicked"]
    results["opt_out_verified"] = optout_result["opt_out_verified"]
    results["opt_out_method"] = optout_result["opt_out_method"]
    results["opt_out_attempts"] = optout_result["opt_out_attempts"]

    # Store opt-out screenshots
    optout_screenshots = optout_result.get("screenshots", {})
    if optout_screenshots:
        results["screenshot_optout"] = optout_screenshots.get("optout_after") or optout_screenshots.get("optout_final")
        results["optout_screenshots"] = optout_screenshots

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

    # ── Step 7: Post-opt-out — clear state & return to homepage ─────
    # After opting out, we need a clean slate before simulating
    # real browsing behaviour.  Many trackers only fire during active
    # navigation (page transitions, product clicks, scrolling), not
    # when sitting idle on one page.

    if results["opt_out_clicked"] == "yes":
        print(f"[*] Opt-out complete. Clearing network logs and returning to homepage...")
        report_status("Clearing network logs after opt-out...", 8)
    else:
        report_status("Preparing post-opt-out monitoring...", 8)

    # 7a. CLEAR all network logs — fresh start.
    captured_requests.clear()
    request_details.clear()

    # 7b. GO BACK to the homepage (ensures we're on the target site
    #     and triggers a fresh page load with post-opt-out cookie state).
    target_base = domain.replace("www.", "")
    try:
        page.goto(url, timeout=PAGE_LOAD_TIMEOUT, wait_until="domcontentloaded")
        report_status("Returned to homepage after opt-out", 9)
        print(f"[*] Returned to homepage: {url}")
    except PlaywrightTimeout:
        print("[!] Homepage reload timed out — continuing")
    except Exception as e:
        print(f"[!] Failed to return to homepage: {e}")

    # 7c. WAIT for homepage to fully load.
    page.wait_for_timeout(3000)

    # 7d. CLEAR network logs again — we only want to capture activity
    #     from the shop browsing flow onward.
    captured_requests.clear()
    request_details.clear()

    # ── Step 8: Simulate real shopping behaviour ────────────────────
    # Trackers often only fire when the user browses products, not
    # just on the homepage.  We: navigate to the shop page → click a
    # product → scroll the product page.  We capture ALL network
    # requests during this entire flow.

    # 8a. Navigate to the shop / all-products page.
    print("[*] Looking for a Shop / All Products link...")
    report_status("Looking for Shop page...", 10)
    shop_clicked = navigate_to_shop(page)

    if shop_clicked:
        print(f'[*] Navigated to shop page via: "{shop_clicked}"')
        report_status(f"Navigated to shop page", 11)
        # WAIT for the shop page to fully load.
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except PlaywrightTimeout:
            pass  # some shop pages never fully idle
        page.wait_for_timeout(5000)
    else:
        print("[!] Could not find a Shop / All Products link.")
        report_status("No shop page found — trying products on current page", 11)
        results["notes"].append("Could not find shop page link; browsing from homepage.")

    # 8b. Click the first product.
    print("[*] Looking for a product to click...")
    report_status("Browsing products...", 12)
    product_clicked = click_first_product(page)

    if product_clicked:
        print("[*] Clicked on a product — monitoring network requests...")
        report_status("Clicked product — monitoring network requests...", 13)
        # Wait for the product page to fully load.
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except PlaywrightTimeout:
            pass
        page.wait_for_timeout(3000)

        # 8c. Scroll down the product page slowly over ~20 seconds
        #     to trigger scroll-based and lazy-loaded trackers.
        report_status("Scrolling product page — monitoring for delayed trackers...", 14)
        print("[*] Scrolling product page for 20s to trigger delayed trackers...")
        try:
            page.mouse.move(640, 450)
            # 10 scroll increments over ~20 seconds.
            for i in range(10):
                page.mouse.wheel(0, 350)
                page.wait_for_timeout(2000)
        except Exception as e:
            print(f"[!] Scroll monitoring error: {e}")

        results["notes"].append(
            f"Browsed to shop page ({shop_clicked or 'homepage'}) and "
            "clicked a product. Scrolled for 20s."
        )
    else:
        print("[!] Could not find a product to click.")
        results["notes"].append(
            "Could not find a product to click; monitored page with scrolling instead."
        )
        # Fall back: scroll and interact with the current page for ~20s.
        report_status("No product found — scrolling current page...", 13)
        report_status("Scrolling page — monitoring for delayed trackers...", 14)
        try:
            page.mouse.move(640, 450)
            for i in range(10):
                page.mouse.wheel(0, 350)
                page.wait_for_timeout(2000)
        except Exception:
            pass

    # ── Step 9: Check for continued tracking ────────────────────────
    # Now look at everything the browser sent during the shopping flow.
    results["trackers_after"] = collect_tracker_hits(captured_requests)
    results["tiktok_trackers_after"] = collect_tiktok_hits(captured_requests)

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
    report_status("Analyzing post-opt-out network traffic...", 15)

    if flagged_domains:
        print(f"\n[!] FLAGGED TRACKER DOMAINS ({len(flagged_domains)}):")
        for fd, info in sorted(flagged_domains.items()):
            print(f"      - {fd}  ({info['count']} requests)  "
                  f"[matched: {info['matched_rule']}]")
        report_status(f"Found {len(flagged_domains)} flagged tracker domains", 16)
    else:
        print("[*] No known tracker domains found in post-opt-out requests.")
        report_status("No tracker domains found after opt-out", 16)

    # Determine verdict — ONLY TikTok tracking triggers FAIL:
    #   - TikTok trackers found after opt-out  → FAIL ("yes")
    #   - No TikTok trackers after opt-out     → PASS ("no")
    #   - Couldn't find/click opt-out          → INCONCLUSIVE
    #
    # All other trackers (Google, Facebook, etc.) are still logged for
    # evidence but do NOT affect the pass/fail determination.
    if results["tiktok_trackers_after"]:
        results["still_tracking"] = "yes"
    elif results["opt_out_clicked"] != "yes":
        results["still_tracking"] = "inconclusive"

    if new_tp_cookie_domains:
        # Check if any new third-party cookie domains match known trackers.
        tracker_cookie_domains = [
            d for d in new_tp_cookie_domains if is_tracker_request(d.lstrip("."))
        ]
        # Log all new tracker cookies for evidence.
        if tracker_cookie_domains:
            print(f"\n[!] NEW tracker cookies set after opt-out:")
            for d in tracker_cookie_domains:
                print(f"      - {d}")
            results["notes"].append(
                f"New tracker cookies after opt-out: "
                f"{json.dumps(tracker_cookie_domains)}"
            )
            # Only upgrade to FAIL if TikTok cookies are among them.
            tiktok_cookie_domains = [
                d for d in tracker_cookie_domains
                if any(tk in d for tk in ["tiktok", "bytedance"])
            ]
            if tiktok_cookie_domains:
                results["still_tracking"] = "yes"

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
        report_status("After screenshot captured", 17)
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
    report_status("Results saved to database", 18)

    # Store detailed request metadata for evidence package.
    results["request_details"] = list(request_details)

    # ── Clean up ────────────────────────────────────────────────────
    context.close()

    # ── Print summary ─────────────────────────────────────────────
    print_summary(results)
    report_status("Scan complete", 19)

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
    print(f"  TikTok after         : {len(results['tiktok_trackers_after'])} "
          f"{results['tiktok_trackers_after']}")

    # Show every flagged domain with request counts.
    flagged = results.get("flagged_domains", {})
    if flagged:
        print(f"\n  FLAGGED DOMAINS (post-opt-out browsing):")
        for fd, info in sorted(flagged.items()):
            print(f"    {fd:45s}  {info['count']:>3} reqs  "
                  f"[{info['matched_rule']}]")

    if results["still_tracking"] == "yes":
        print(f"\n  *** TIKTOK TRACKING CONTINUES AFTER OPT-OUT ***")
    elif results["still_tracking"] == "inconclusive":
        print(f"\n  *** INCONCLUSIVE — Opt-out could not be verified ***")
    else:
        print(f"\n  No TikTok tracking after opt-out: OK")

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
                    "tiktok_trackers_after": [],
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
