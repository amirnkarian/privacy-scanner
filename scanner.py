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
import multiprocessing
import os
import re
import sys
import threading
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
PAGE_LOAD_TIMEOUT = 15_000  # 15 seconds per page navigation

# Maximum time (seconds) for the ENTIRE scan of a single site.
MAX_SCAN_TIME = 90  # 90 seconds hard cap

# How long (seconds) to scroll/monitor after clicking a product.
POST_PRODUCT_MONITOR = 15


class ScanTimeout(Exception):
    """Raised when a site scan exceeds MAX_SCAN_TIME."""

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
    "analytics-ipv6.tiktokw.us",
    "www.tiktok.com",
    "business-api.tiktok.com",
    "mcs-va.tiktok.com",
    "mon.tiktok.com",
]

# Frozen set for O(1) exact hostname lookups — NO substring matching.
_TIKTOK_DOMAIN_SET = frozenset(TIKTOK_TRACKER_DOMAINS)

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
    """Check if a request URL goes to an EXACT TikTok tracker domain.

    Uses urlparse to extract the hostname — no substring matching.
    Returns the matched hostname, or None.
    """
    try:
        hostname = urlparse(request_url).hostname
        if hostname and hostname.lower() in _TIKTOK_DOMAIN_SET:
            return hostname.lower()
    except Exception:
        pass
    return None


def collect_tiktok_hits(captured_requests):
    """Return sorted list of unique TikTok tracker domains contacted."""
    found = set()
    for url in captured_requests:
        match = is_tiktok_request(url)
        if match:
            found.add(match)
    return sorted(found)


def collect_tiktok_urls(captured_requests):
    """Return list of full URLs that matched TikTok tracker domains."""
    urls = []
    for url in captured_requests:
        if is_tiktok_request(url):
            urls.append(url)
    return urls


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
# Case-insensitive matching — stored in title case but compared lowercase.
_FOOTER_PRIVACY_TEXTS = [
    # Privacy choices
    "Your Privacy Rights and Choices",
    "Your Privacy Rights",
    "Your Privacy Choices",
    "Privacy Choices",
    "Privacy Options",
    "Your Choices",
    "Your California Privacy Rights",
    # Cookie management
    "Cookie Preferences",
    "Cookie Settings",
    "Cookie Management",
    "Manage Cookies",
    "Cookie Consent",
    "Manage Your Cookie Preferences",
    "Cookie Policy",
    # Privacy settings
    "Privacy Settings",
    "Privacy Preferences",
    "Manage Privacy",
    "Privacy Center",
    # Do Not Sell variations
    "Do Not Sell My Personal Information",
    "Do Not Sell or Share My Personal Information",
    "Do Not Sell My Info",
    "Do Not Sell or Share",
    "Do Not Sell",
    # Advertising
    "Ad Preferences",
    "Advertising Preferences",
    "AdChoices",
    # Opt out
    "Opt Out",
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
    Strategy 2: Find privacy/cookie links anywhere on the page — footer,
    floating bars, sidebars, legal sections, expandable menus, etc.
    Click them and handle whatever opens (modal, preference panel, new page).
    Returns dict with keys: strategy, clicked, element.
    """
    attempt = {"strategy": "footer_link", "clicked": False, "element": None}

    # Dismiss any marketing popups that may block footer clicks
    _dismiss_popups(page)

    # Scroll to the very bottom to reveal lazy-loaded footer content.
    print("[*] Scrolling to bottom of page to find privacy links...")
    _scroll_to_bottom(page)

    # Dismiss popups again after scrolling (some appear on scroll)
    _dismiss_popups(page)

    # Try expanding "More", "Legal", "Policies" sections in footer
    for expand_text in ["More", "Legal", "Policies", "Information", "About",
                        "Company", "Help", "Customer Service", "Resources"]:
        try:
            for sel in [
                f'footer button:has-text("{expand_text}")',
                f'footer summary:has-text("{expand_text}")',
                f'footer [role="button"]:has-text("{expand_text}")',
                f'footer h3:has-text("{expand_text}")',
                f'footer h4:has-text("{expand_text}")',
            ]:
                loc = page.locator(sel).first
                if loc.is_visible(timeout=300):
                    loc.click(timeout=2000)
                    page.wait_for_timeout(500)
                    break
        except Exception:
            continue

    # Record the current URL to detect page navigations
    url_before = page.url

    # Use JavaScript to find ALL matching links/buttons on the page
    # This avoids Playwright's :has-text() issues with hidden elements
    print("[*] Searching entire page for privacy/cookie links...")
    try:
        matches = page.evaluate("""(searchTexts) => {
            const results = [];
            const seen = new Set();
            // Search all clickable elements
            const els = document.querySelectorAll('a, button, [role="link"], [role="button"], span[onclick], div[onclick]');
            for (const el of els) {
                const text = (el.textContent || '').trim();
                if (!text || text.length > 200) continue;
                const textLower = text.toLowerCase();
                for (const searchText of searchTexts) {
                    if (textLower.includes(searchText.toLowerCase())) {
                        const rect = el.getBoundingClientRect();
                        const style = window.getComputedStyle(el);
                        // Check visibility
                        if (style.display === 'none' || style.visibility === 'hidden') continue;
                        if (rect.width < 5 || rect.height < 5) continue;
                        const key = searchText + '|' + (el.getAttribute('href') || '') + '|' + text.slice(0, 50);
                        if (seen.has(key)) continue;
                        seen.add(key);
                        results.push({
                            matchedText: searchText,
                            elementText: text.slice(0, 100),
                            tag: el.tagName.toLowerCase(),
                            href: el.getAttribute('href') || '',
                            top: rect.top,
                            inFooter: !!el.closest('footer'),
                            inFixed: style.position === 'fixed' || style.position === 'sticky',
                            // Unique selector for re-finding
                            xpath: (() => {
                                const path = [];
                                let node = el;
                                while (node && node.nodeType === 1) {
                                    let idx = 1;
                                    let sib = node.previousElementSibling;
                                    while (sib) { if (sib.tagName === node.tagName) idx++; sib = sib.previousElementSibling; }
                                    path.unshift(node.tagName.toLowerCase() + '[' + idx + ']');
                                    node = node.parentElement;
                                }
                                return '/' + path.join('/');
                            })()
                        });
                        break;  // One match per element is enough
                    }
                }
            }
            // Prioritize: footer links first, then fixed/floating bars, then rest
            results.sort((a, b) => {
                if (a.inFooter && !b.inFooter) return -1;
                if (!a.inFooter && b.inFooter) return 1;
                if (a.inFixed && !b.inFixed) return -1;
                if (!a.inFixed && b.inFixed) return 1;
                return 0;
            });
            return results;
        }""", _FOOTER_PRIVACY_TEXTS)
        print(f"[*] Found {len(matches)} privacy link candidates")
        for m in matches[:5]:
            loc_desc = "footer" if m["inFooter"] else ("floating" if m["inFixed"] else "page")
            print(f'    [{loc_desc}] "{m["elementText"][:60]}" ({m["tag"]})')
    except Exception as e:
        print(f"[!] JS privacy link search failed: {e}")
        matches = []

    # Try clicking each match
    for match in matches:
        try:
            text = match["matchedText"]
            elem_text = match["elementText"]

            # Re-find the element using XPath
            xpath = match["xpath"]
            try:
                locator = page.locator(f'xpath=/{xpath}')
                if not locator.is_visible(timeout=500):
                    # Try text-based fallback
                    locator = page.locator(f'{match["tag"]}:has-text("{text}")').first
                    if not locator.is_visible(timeout=500):
                        continue
            except Exception:
                locator = page.locator(f'{match["tag"]}:has-text("{text}")').first
                try:
                    if not locator.is_visible(timeout=500):
                        continue
                except Exception:
                    continue

            # Click it
            try:
                locator.click(timeout=5000)
            except Exception:
                try:
                    locator.click(timeout=3000, force=True)
                except Exception:
                    continue

            loc_desc = "footer" if match["inFooter"] else ("floating bar" if match["inFixed"] else "page")
            print(f'[*] Clicked privacy link in {loc_desc}: "{text}"')
            page.wait_for_timeout(3000)

            # Check if we navigated to a new page
            url_after = page.url
            navigated_away = url_after != url_before

            if navigated_away:
                print(f"[*] Navigated to privacy page: {url_after}")
                page.wait_for_timeout(3000)

                # On the privacy page, look for manage/settings buttons
                manage_texts = [
                    "Manage Your Cookie Preferences",
                    "Manage Cookie Preferences",
                    "Cookie Preferences",
                    "Cookie Settings",
                    "Manage Cookies",
                    "Manage Preferences",
                    "Manage Privacy Settings",
                    "Cookie Consent Settings",
                ]
                for mt in manage_texts:
                    sub_clicked = try_click_button(page, [mt])
                    if sub_clicked:
                        print(f'[*] Clicked: "{sub_clicked}" on privacy page')
                        page.wait_for_timeout(3000)
                        break

            # Try to interact with whatever appeared (modal, panel, or page)
            result = _interact_with_preference_panel(page)
            if result:
                page.wait_for_timeout(2000)
                panel_gone = _is_preference_panel_dismissed(page)
                attempt["clicked"] = True
                attempt["verified"] = True
                attempt["element"] = f"Footer ({text}) → {result}"
                if panel_gone:
                    attempt["element"] += " [panel dismissed]"
                return attempt

            # If nothing worked, go back if we navigated
            if navigated_away:
                try:
                    page.goto(original_url, timeout=PAGE_LOAD_TIMEOUT, wait_until="domcontentloaded")
                    page.wait_for_timeout(2000)
                    _scroll_to_bottom(page)
                except Exception:
                    pass

        except Exception:
            continue

    # Also try the CCPA toggle icon (a blue toggle/slider icon)
    try:
        for icon_sel in [
            'a[href*="privacy"]',
            '[class*="ccpa"]',
            '[class*="privacy-choices"]',
            '[class*="privacychoices"]',
            '[id*="ccpa"]',
            '[id*="privacy"]',
            'img[alt*="Privacy"]',
            'img[alt*="CCPA"]',
            'img[alt*="privacy choices"]',
            'img[alt*="Your Privacy Choices"]',
            'a[href*="optout"]',
            'a[href*="opt-out"]',
        ]:
            # Search in footer first, then anywhere on page
            for scope in ['footer', '']:
                full_sel = f'{scope} {icon_sel}'.strip() if scope else icon_sel
                try:
                    locator = page.locator(full_sel).first
                    if locator.is_visible(timeout=500):
                        locator.click(timeout=3000)
                        print(f"[*] Clicked CCPA/privacy icon: {full_sel}")
                        page.wait_for_timeout(3000)
                        result = _interact_with_preference_panel(page)
                        if result:
                            attempt["clicked"] = True
                            attempt["verified"] = True
                            attempt["element"] = f"CCPA icon ({full_sel}) → {result}"
                            return attempt
                        break
                except Exception:
                    continue
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
        for selector in ['.cookie-close', '[class*="dismiss"]',
                         '.close-button', '[aria-label="Close"]']:
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
    "Browse",
    # Category/department pages (fashion/apparel sites)
    "Women",
    "Men",
    "Clothing",
    "Dresses",
    "Accessories",
    "What's New",
    "Sale",
    "Featured",
    # Large retailers / department stores
    "Shop by Category",
    "Furniture",
    "Home Decor",
    "Outdoor",
    "Living Room",
    "Bedroom",
    "Kitchen",
    "Rugs",
    "Lighting",
    "Bath",
]

# Common shop/collection URL path patterns to try as fallback.
SHOP_URL_PATTERNS = [
    "/collections/all",
    "/collections",
    "/products",
    "/shop",
    "/shop-all",
    "/shop/all",
    "/catalog",
    "/women",
    "/men",
    "/new-arrivals",
    "/clothing",
    "/sale",
    "/furniture",
    "/c/all",
]


def navigate_to_shop(page):
    """
    Try to find and click a link to the shop / all-products page.

    Strategy:
      1. Look for visible shop links in the main nav/header.
      2. Hover over top-level nav items to reveal dropdown menus, click subcategories.
      3. If not found, try opening a hamburger/mobile menu first.
      4. If still not found, try navigating directly to common URL patterns.

    Returns the link text or URL pattern that was used, or None.
    """
    # URLs that look like store locators / non-shopping pages
    _BAD_PATHS = ["/stores", "/store-locator", "/find-a-store", "/locations",
                  "/about", "/contact", "/careers", "/help", "/faq",
                  "/privacy", "/terms", "/legal"]

    def _is_bad_landing(url):
        path = urlparse(url).path.lower().rstrip("/")
        return any(path == bp or path.startswith(bp + "/") for bp in _BAD_PATHS)

    # 1. Look for visible shop links in the main navigation.
    #    After clicking, verify the URL actually changed (not just a dropdown).
    pre_nav_url = page.url
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
                    page.wait_for_timeout(2000)
                    if page.url != pre_nav_url and not _is_bad_landing(page.url):
                        return text
                    # URL didn't change or bad landing — try next
        except Exception:
            continue

    # 2. Hover over top-level nav items to trigger dropdown menus,
    #    then look for subcategory links in the revealed dropdown.
    print("[*] Trying hover-triggered nav dropdowns...")
    try:
        top_nav_items = page.evaluate("""() => {
            const items = [];
            const navLinks = document.querySelectorAll('nav a, header nav a, [role="navigation"] a');
            for (const a of navLinks) {
                const rect = a.getBoundingClientRect();
                const style = window.getComputedStyle(a);
                if (style.display === 'none' || style.visibility === 'hidden') continue;
                if (rect.width < 20 || rect.height < 10) continue;
                if (rect.top > 100) continue;  // Only top-level nav
                const text = (a.textContent || '').trim();
                if (text && text.length < 30) {
                    items.push({text: text, x: rect.x + rect.width/2, y: rect.y + rect.height/2});
                }
            }
            return items.slice(0, 8);
        }""")
        for item in top_nav_items:
            try:
                # Hover to trigger dropdown
                page.mouse.move(item["x"], item["y"])
                page.wait_for_timeout(1000)
                # Look for newly visible subcategory links
                sub_link = page.evaluate("""() => {
                    const links = document.querySelectorAll('a[href]');
                    for (const a of links) {
                        const href = (a.getAttribute('href') || '').toLowerCase();
                        const text = (a.textContent || '').trim().toLowerCase();
                        if (!href || href === '/' || href === '#') continue;
                        const rect = a.getBoundingClientRect();
                        const style = window.getComputedStyle(a);
                        if (style.display === 'none' || style.visibility === 'hidden') continue;
                        if (rect.width < 10 || rect.height < 10) continue;
                        // Look for category/product links in dropdown
                        const patterns = ['/collections/', '/products', '/shop/', '/c/', '/category/'];
                        if (patterns.some(p => href.includes(p))) {
                            return {href: a.getAttribute('href'), text: text.slice(0, 50)};
                        }
                    }
                    return null;
                }""")
                if sub_link:
                    full_url = sub_link["href"]
                    if not full_url.startswith("http"):
                        parsed = urlparse(page.url)
                        full_url = f"{parsed.scheme}://{parsed.netloc}{full_url}"
                    page.goto(full_url, timeout=PAGE_LOAD_TIMEOUT, wait_until="domcontentloaded")
                    page.wait_for_timeout(2000)
                    if page.url != pre_nav_url and not _is_bad_landing(page.url):
                        print(f"[*] Navigated via hover dropdown: {item['text']} → {sub_link['text']}")
                        return f"Hover: {item['text']} → {sub_link['text']}"
            except Exception:
                continue
    except Exception:
        pass

    # 3. Try opening a hamburger / mobile menu and look again.
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
                    page.wait_for_timeout(2000)
                    if page.url != pre_nav_url and not _is_bad_landing(page.url):
                        return text
            except Exception:
                continue

    # 4. Fallback: try navigating directly to common URL patterns.
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


def navigate_to_product(page):
    """
    Navigate to a product page. No clicking, no visibility checks.
    Just find product URLs and goto them directly.

    Returns (success: bool, product_url: str or None).
    """
    page_origin = urlparse(page.url)
    base_url = f"{page_origin.scheme}://{page_origin.hostname}"
    target_host = (page_origin.hostname or "").lower().replace("www.", "")

    def _is_same_site(url):
        """Filter out external URLs (e.g. onetrust.com/products/)."""
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return True  # relative URL — same site
            host = parsed.hostname.lower().replace("www.", "")
            return host == target_host or host.endswith("." + target_host)
        except Exception:
            return False

    EXTRACT_PRODUCT_URLS_JS = """() => {
        const selectors = [
            'a[href*="/products/"]',
            'a[href*="/product/"]',
            'a[href*="/product.do"]',
            'a[href*="/browse/product"]',
            'a[href*="/dp/"]',
            'a[href*="/item/"]',
            'a[href*="/p/"]',
            'a[href*="pid="]',
            'a[href*="product_id="]',
        ];
        const hrefs = new Set();
        for (const sel of selectors) {
            for (const a of document.querySelectorAll(sel)) {
                const href = a.href || a.getAttribute('href');
                if (href && href !== '/' && href !== '#') hrefs.add(href);
            }
        }
        return [...hrefs];
    }"""

    def _extract_from_html(html):
        """Regex fallback: extract product URLs from raw HTML source."""
        urls = list(set(re.findall(
            r'href=["\']([^"\']*?/products?/[a-zA-Z0-9][a-zA-Z0-9\-_]*)',
            html
        )))
        urls += list(set(re.findall(
            r'href=["\']([^"\']*?/browse/product[^"\']*)',
            html
        )))
        urls += list(set(re.findall(
            r'href=["\']([^"\']*?[?&]pid=[^"\']*)',
            html
        )))
        return urls

    def _try_navigate_to_product(product_urls):
        """Try navigating to the first product URL. Returns (success, url)."""
        for target in product_urls[:3]:
            if target.startswith("/"):
                target = base_url + target
            elif not target.startswith("http"):
                target = base_url + "/" + target
            print(f"  Navigating to product: {target[:100]}")
            try:
                page.goto(target, timeout=15000, wait_until="domcontentloaded")
                page.wait_for_timeout(3000)
                print(f"  PRODUCT PAGE REACHED: {page.url}")
                return True, page.url
            except Exception as e:
                print(f"  Navigation failed: {e}")
                continue
        return False, None

    # Step 1: Try the CURRENT page first (STEP 3 already navigated to a shop page)
    print(f"  Checking current page for product URLs: {page.url[:80]}")
    product_urls = page.evaluate(EXTRACT_PRODUCT_URLS_JS)
    product_urls = [u for u in product_urls if _is_same_site(u)]
    print(f"  querySelectorAll found {len(product_urls)} same-site product URLs on current page")
    for i, url in enumerate(product_urls[:5]):
        print(f"    [{i}] {url[:100]}")

    if product_urls:
        success, url = _try_navigate_to_product(product_urls)
        if success:
            return True, url

    # Step 1b: Try regex on current page HTML
    if not product_urls:
        print("  No product URLs from selectors — trying regex on current page HTML...")
        html = page.evaluate("() => document.documentElement.innerHTML")
        product_urls = _extract_from_html(html)
        product_urls = [u for u in product_urls if _is_same_site(u)]
        print(f"  Regex found {len(product_urls)} same-site product URLs")
        for i, url in enumerate(product_urls[:5]):
            print(f"    [{i}] {url[:100]}")
        if product_urls:
            success, url = _try_navigate_to_product(product_urls)
            if success:
                return True, url

    # Step 2: Try common shop/collection pages as fallback
    shop_paths = ["/collections/all", "/collections", "/products", "/shop", "/shop-all",
                  "/shop/all", "/browse", "/catalog"]
    for path in shop_paths:
        full_url = base_url + path
        print(f"  Trying shop page: {full_url}")
        try:
            resp = page.goto(full_url, timeout=15000, wait_until="domcontentloaded")
            if not resp or resp.status != 200:
                continue
            print(f"  Landed on shop page: {page.url}")
            page.wait_for_timeout(5000)

            # Extract product URLs from this page
            product_urls = page.evaluate(EXTRACT_PRODUCT_URLS_JS)
            product_urls = [u for u in product_urls if _is_same_site(u)]
            print(f"  querySelectorAll found {len(product_urls)} same-site product URLs")
            for i, url in enumerate(product_urls[:5]):
                print(f"    [{i}] {url[:100]}")

            if not product_urls:
                html = page.evaluate("() => document.documentElement.innerHTML")
                product_urls = _extract_from_html(html)
                product_urls = [u for u in product_urls if _is_same_site(u)]
                print(f"  Regex found {len(product_urls)} same-site product URLs")
                for i, url in enumerate(product_urls[:5]):
                    print(f"    [{i}] {url[:100]}")

            if product_urls:
                success, url = _try_navigate_to_product(product_urls)
                if success:
                    return True, url
        except Exception as e:
            print(f"  {path} failed: {e}")
            continue

    print("  No product URLs found anywhere.")
    return False, None


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
    TOTAL_STEPS = 20

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
        "screenshot_product": None,
        "product_page_url": None,
        "total_requests_captured": 0,
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

    scan_start_time = time.time()

    def report_status(message, step):
        """Send a status update via the callback, if one was provided."""
        elapsed = time.time() - scan_start_time
        results["scan_timeline"].append({
            "step": step,
            "message": message,
            "timestamp": datetime.now().isoformat(),
        })
        if status_callback:
            status_callback(message, step, TOTAL_STEPS, elapsed)

    domain = get_domain(url)
    print(f"\n{'=' * 60}")
    print(f"  SCANNING: {url}")
    print(f"{'=' * 60}")
    report_status(f"Initializing scan for {domain}", 1)

    # ── Step 1: Open a new browser context ──────────────────────────
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

    # Intercept navigator.sendBeacon() — must be added BEFORE creating pages.
    context.add_init_script("""
        (function() {
            const origBeacon = navigator.sendBeacon.bind(navigator);
            navigator.sendBeacon = function(url, data) {
                try { fetch(url, {method:'POST', body: data, keepalive: true}).catch(()=>{}); } catch(e) {}
                return origBeacon(url, data);
            };
        })();
    """)

    # No internal timeout — enforced by multiprocessing.Process at the caller level.

    # Initialize capture lists (fallback if Phase 2 never reached).
    captured_requests_after = []
    request_details_after = []
    capture_start_time = None

    timed_out = False
    all_cookies = []
    tp_cookies_before = []
    safe_domain = domain.replace(":", "_")  # handle ports in domain
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: Visit site and complete opt-out
    # ═══════════════════════════════════════════════════════════════
    page = context.new_page()

    # Phase 1 listener — captures "before" requests only.
    captured_requests_phase1 = []

    def on_request_phase1(request):
        captured_requests_phase1.append(request.url)

    page.on("request", on_request_phase1)

    print("[*] Phase 1: Visiting site and completing opt-out...")
    report_status("Phase 1: Visiting website...", 2)

    try:
        page.goto(url, timeout=PAGE_LOAD_TIMEOUT, wait_until="domcontentloaded")
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

    try:  # Global timeout wrapper

        # STEP 1: Wait 5 seconds for full page load.
        page.wait_for_timeout(5000)


        # ── Step 4: Take "before" screenshot ────────────────────────────
        before_path = os.path.join(SCREENSHOTS_DIR, f"{safe_domain}_before.png")
        try:
            page.screenshot(path=before_path, full_page=True)
            results["screenshot_before"] = before_path
            print(f"[*] 'Before' screenshot saved: {before_path}")
            report_status("Before screenshot captured", 4)
        except Exception as e:
            print(f"[!] Screenshot failed: {e}")



        # ── Step 5: Record initial trackers ─────────────────────────────
        results["trackers_before"] = collect_tracker_hits(captured_requests_phase1)

        # Also check for third-party cookies.
        all_cookies = context.cookies()
        results["cookies_before_details"] = all_cookies
        tp_cookies_before = find_third_party_cookies(all_cookies, domain)

        # ── DIAGNOSTIC: Log TikTok requests found BEFORE opt-out ───────
        tiktok_before_urls = collect_tiktok_urls(captured_requests_phase1)
        tiktok_before_domains = collect_tiktok_hits(captured_requests_phase1)
        print(f"\n>>> BEFORE OPT-OUT: Found {len(tiktok_before_urls)} TikTok requests: "
              f"{tiktok_before_domains}")
        for tu in tiktok_before_urls:
            print(f">>>   {tu[:120]}")

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
        print("STEP 2: Looking for opt-out mechanism...")
        report_status("STEP 2: Looking for opt-out mechanism...", 6)

        try:

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

            # Log opt-out type for console visibility.
            for att in optout_result.get("opt_out_attempts", []):
                if att.get("clicked"):
                    strategy = att.get("strategy", "")
                    if strategy == "banner_popup":
                        print(f"STEP 2: Detected TYPE A (popup/banner) — {att.get('element', '')}")
                    elif strategy == "footer_link":
                        print(f"STEP 2: Detected TYPE B (footer link) — {att.get('element', '')}")
                    elif strategy == "js_consent_api":
                        print(f"STEP 2: Detected TYPE C (JavaScript API) — {att.get('element', '')}")
                    break
        except ScanTimeout:
            raise
        except Exception as e:
            print(f"[!] STEP 2: Opt-out failed ({e}) — skipping to next step")
            results["notes"].append(f"Opt-out step failed: {e}")

        # ── DIAGNOSTIC: Log opt-out result ──────────────────────────────
        if results["opt_out_verified"] == "yes":
            print(f"\n>>> OPT-OUT COMPLETED: {results['opt_out_method']}")
            report_status(f'Opted out via: {results["opt_out_method"]}', 7)
        elif results["opt_out_clicked"] == "yes":
            print(f"\n>>> OPT-OUT CLICKED (unverified): {results.get('opt_out_method', 'unknown')}")
            results["notes"].append(
                "Opt-out was clicked but banner may still be visible — unverified."
            )
            report_status("Opt-out clicked but banner still visible", 7)
        else:
            print(f"\n>>> OPT-OUT NOT FOUND — no banner/link detected")
            results["notes"].append("No cookie consent banner found.")
            report_status("No cookie consent banner found", 7)

        # ═══════════════════════════════════════════════════════════════
        # END OF PHASE 1 — Close the page.
        # Cookies and localStorage are preserved in the browser context.
        # ═══════════════════════════════════════════════════════════════

        print("\n>>> PHASE 1 COMPLETE — closing page, cookies preserved in context")
        try:
            page.close()
        except Exception:
            pass

        # ═══════════════════════════════════════════════════════════════
        # PHASE 2: Test if tracking persists on a BRAND NEW page.
        #
        # By opening a new page in the same context, we simulate a user
        # coming back to the site AFTER having opted out.  The opt-out
        # preferences are stored in cookies/localStorage which persist.
        #
        # We do NOT attach any listener until the product page is fully
        # loaded. This eliminates TikTok requests from initial page
        # setup, script initialization, and consent banner processing.
        # ═══════════════════════════════════════════════════════════════
        report_status("Phase 2: Testing post-opt-out tracking...", 8)
        page = context.new_page()

        # ── Navigate to homepage (NO listener) ─────────────────────────
        try:
            page.goto(url, timeout=PAGE_LOAD_TIMEOUT, wait_until="domcontentloaded")
            page.wait_for_timeout(3000)
            print(f"[*] Phase 2: Homepage loaded: {url}")
            report_status("Phase 2: Homepage loaded", 9)
        except PlaywrightTimeout:
            print("[!] Phase 2: Homepage load timed out — continuing")
        except Exception as e:
            print(f"[!] Phase 2: Homepage load failed: {e}")


        # ── Navigate to shop page (NO listener) ───────────────────────
        shop_clicked = None
        try:
            print("STEP 3: Looking for shop/category page...")
            report_status("STEP 3: Looking for shop/category page...", 10)
            shop_clicked = navigate_to_shop(page)

            if shop_clicked:
                print(f"STEP 3: Navigated to category page: {page.url}")
                report_status("STEP 3: Navigated to category page", 11)
                page.wait_for_timeout(3000)

            else:
                print("STEP 3: Could not find shop/category page.")
                report_status("STEP 3: No shop page found — using current page", 11)
                results["notes"].append("Could not find shop page link; browsing from homepage.")
        except ScanTimeout:
            raise
        except Exception as e:
            print(f"[!] STEP 3: Navigation failed ({e}) — skipping to next step")
            results["notes"].append(f"Navigation step failed: {e}")

        # ── Click a product (NO listener) ──────────────────────────────
        print("STEP 4: Looking for products...")
        report_status("STEP 4: Looking for products...", 12)
        on_product_page = False

        try:
            report_status("STEP 4: Clicking product...", 13)

            on_product_page, product_url = navigate_to_product(
                page
            )

            if on_product_page:
                results["product_page_url"] = product_url
                print(f"STEP 4: CONFIRMED on product page: {product_url}")
            else:
                print("STEP 4: ALL product click attempts FAILED — marking INCONCLUSIVE")
                results["notes"].append(
                    "Could not navigate to a product page; scan marked INCONCLUSIVE."
                )
                results["still_tracking"] = "inconclusive"

        except ScanTimeout:
            raise
        except Exception as e:
            print(f"[!] STEP 4: Product click failed ({e}) — marking INCONCLUSIVE")
            results["notes"].append(f"Product click step failed: {e}")
            results["still_tracking"] = "inconclusive"

        # ── Take product page screenshot ───────────────────────────────
        current_url = page.url

        if on_product_page:
            print(f"\n>>> EVIDENCE SCREENSHOT taken on: {current_url}")
            results["product_page_url"] = current_url

            product_ss_path = os.path.join(SCREENSHOTS_DIR, f"{safe_domain}_product.png")
            try:
                page.screenshot(path=product_ss_path, full_page=False, timeout=5000)
                results["screenshot_product"] = product_ss_path
                print(f"STEP 5: Product screenshot saved: {product_ss_path}")
            except Exception as e:
                print(f"STEP 5: Screenshot failed: {e}")
            report_status("STEP 5: Product page screenshot taken", 14)
        else:
            print(f"STEP 5: SKIPPING screenshot — not on a product page ({current_url})")
            report_status("STEP 5: No product page found — skipping screenshot", 14)

        # ═══════════════════════════════════════════════════════════════
        # NOW — Attach the monitoring listener.
        # This is the ONLY list that matters for violation detection.
        # Only requests from active browsing on the product page count.
        # ═══════════════════════════════════════════════════════════════
        capture_start_time = time.time()
        captured_requests_after = []
        request_details_after = []

        def on_request_after(request):
            req_time = time.time()
            captured_requests_after.append(request.url)
            try:
                headers = dict(request.headers) if request.headers else {}
            except Exception:
                headers = {}
            try:
                post_data_length = len(request.post_data) if request.post_data else 0
            except Exception:
                post_data_length = 0
            request_details_after.append({
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type,
                "post_data_length": post_data_length,
                "timestamp": req_time,
                "relative_time": req_time - capture_start_time,
                "headers": headers,
            })
            # Log TikTok requests the instant they arrive.
            tiktok_match = is_tiktok_request(request.url)
            if tiktok_match:
                relative = req_time - capture_start_time
                print(f">>> TIKTOK REQUEST at +{relative:.1f}s on {page.url[:60]}: "
                      f"{request.url[:120]}")

        page.on("request", on_request_after)
        print(f">>> MONITORING STARTED at {capture_start_time:.0f} — "
              f"scrolling product page for {POST_PRODUCT_MONITOR}s")
        report_status("STEP 6: Monitoring network during active browsing", 15)

        # ── Scroll product page for 15 seconds (active browsing) ──────
        try:
            page.mouse.move(640, 450)
            scroll_end = time.time() + POST_PRODUCT_MONITOR
            while time.time() < scroll_end:

                page.mouse.wheel(0, 350)
                page.wait_for_timeout(1500)
        except ScanTimeout:
            raise
        except Exception as e:
            print(f"STEP 6: Scroll interrupted ({e}) — continuing with what we captured")

        # Remove listener to stop capturing.
        try:
            page.remove_listener("request", on_request_after)
        except Exception:
            pass

        # ── DIAGNOSTIC: Log AFTER OPT-OUT results ─────────────────────
        tiktok_after_urls = collect_tiktok_urls(captured_requests_after)
        tiktok_after_domains = collect_tiktok_hits(captured_requests_after)
        print(f"\n>>> AFTER OPT-OUT: Found {len(tiktok_after_urls)} TikTok requests: "
              f"{tiktok_after_domains}")
        for rd in request_details_after:
            if is_tiktok_request(rd["url"]):
                print(f">>>   +{rd['relative_time']:.1f}s  {rd['url'][:120]}")
        print(f">>> Total requests in monitoring window: {len(captured_requests_after)}")

        if on_product_page:
            results["notes"].append(
                f"Product page: {current_url}. "
                f"Monitored for {POST_PRODUCT_MONITOR}s."
            )

    except Exception as e:
        # Global timeout (soft or hard) or catastrophic error — save whatever we captured.
        timed_out = True
        elapsed = time.time() - scan_start_time
        print(f"\n[!!!] SCAN TIMEOUT/ERROR after {elapsed:.0f}s: {e}")
        results["notes"].append(f"Scan timed out after {elapsed:.0f}s: {e}")
        report_status(f"Scan timed out after {elapsed:.0f}s — saving partial results", 15)

    # ── Check for continued tracking ──────────────────────────────
    # Process ONLY requests captured by the NEW listener (after STEP 5).
    results["total_requests_captured"] = len(captured_requests_after)
    results["trackers_after"] = collect_tracker_hits(captured_requests_after)
    results["tiktok_trackers_after"] = collect_tiktok_hits(captured_requests_after)

    # Group ALL post-opt-out requests by domain for the detailed report.
    request_domains = group_requests_by_domain(captured_requests_after)

    # Flag every request domain that matches a tracker.
    flagged_domains = {}
    for req_domain, count in request_domains.items():
        match = is_tracker_request(req_domain)
        if match:
            flagged_domains[req_domain] = {"count": count, "matched_rule": match}

    # Re-check cookies — were new third-party cookies set after opt-out?
    # If timed out, the browser context may already be unusable.
    new_tp_cookie_domains = []
    try:
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
    except Exception as e:
        print(f"[!] Could not re-check cookies (context may be closed): {e}")

    # ── Print detailed network report ──────────────────────────────
    print(f"\n[*] === POST-OPT-OUT NETWORK REPORT ===")
    print(f"[*] Total requests captured (after window): {len(captured_requests_after)}")
    print(f"[*] Unique domains contacted: {len(request_domains)}")
    report_status("Analyzing post-opt-out network traffic...", 16)

    if flagged_domains:
        print(f"\n[!] FLAGGED TRACKER DOMAINS ({len(flagged_domains)}):")
        for fd, info in sorted(flagged_domains.items()):
            print(f"      - {fd}  ({info['count']} requests)  "
                  f"[matched: {info['matched_rule']}]")
        report_status(f"Found {len(flagged_domains)} flagged tracker domains", 17)
    else:
        print("[*] No known tracker domains found in post-opt-out requests.")
        report_status("No tracker domains found after opt-out", 17)

    # Determine verdict — ONLY TikTok tracking triggers FAIL:
    #   - TikTok trackers found after opt-out  → FAIL ("yes")
    #   - Scan timed out, no TikTok found yet  → TIMEOUT
    #   - Couldn't find/click opt-out          → INCONCLUSIVE
    #   - No TikTok trackers after opt-out     → PASS ("no")
    #
    # All other trackers (Google, Facebook, etc.) are still logged for
    # evidence but do NOT affect the pass/fail determination.
    if results["tiktok_trackers_after"] and results["opt_out_clicked"] == "yes":
        # ── Timestamp analysis: distinguish real violations from false positives ──
        # Collect relative timestamps of every TikTok request.
        tiktok_request_times = []
        for rd in request_details_after:
            if is_tiktok_request(rd["url"]):
                tiktok_request_times.append(rd.get("relative_time", 0))

        has_late_requests = any(t > 5.0 for t in tiktok_request_times)
        all_early = all(t <= 2.0 for t in tiktok_request_times) if tiktok_request_times else True

        if has_late_requests:
            # TikTok requests >5s after monitoring started = TRUE violation.
            results["still_tracking"] = "yes"
            late_times = [f"+{t:.1f}s" for t in tiktok_request_times if t > 5.0]
            print(f"\n>>> VERDICT: FAIL — TikTok requests found >5s after monitoring started: "
                  f"{late_times}")
            print(f">>>   All TikTok request times: "
                  f"{[f'+{t:.1f}s' for t in tiktok_request_times]}")
        elif all_early:
            # All TikTok requests within 2s = likely cached script initialization.
            results["still_tracking"] = "inconclusive"
            results["notes"].append(
                "POSSIBLE FALSE POSITIVE: All TikTok requests occurred within 2s of "
                "monitoring start — likely cached script initialization, not active tracking."
            )
            print(f"\n>>> VERDICT: INCONCLUSIVE (POSSIBLE FALSE POSITIVE) — "
                  f"all {len(tiktok_request_times)} TikTok requests within 2s "
                  f"(likely cached init): "
                  f"{[f'+{t:.1f}s' for t in tiktok_request_times]}")
        else:
            # TikTok requests between 2-5s — inconclusive.
            results["still_tracking"] = "inconclusive"
            results["notes"].append(
                "TikTok requests found between 2-5s after monitoring start — "
                "could be delayed initialization. Marking as inconclusive."
            )
            print(f"\n>>> VERDICT: INCONCLUSIVE — TikTok requests found but all within 5s: "
                  f"{[f'+{t:.1f}s' for t in tiktok_request_times]}")
    elif timed_out:
        results["still_tracking"] = "timeout"
        print(f"\n>>> VERDICT: TIMEOUT — scan exceeded {MAX_SCAN_TIME}s limit")
    elif results["opt_out_clicked"] != "yes":
        results["still_tracking"] = "inconclusive"
        print(f"\n>>> VERDICT: INCONCLUSIVE — opt-out was not clicked "
              f"(opt_out_found={results['opt_out_found']}, "
              f"opt_out_clicked={results['opt_out_clicked']})")
    else:
        print(f"\n>>> VERDICT: PASS — no TikTok tracking after opt-out "
              f"({len(captured_requests_after)} total requests captured)")

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
    # Skip domain verification and screenshots if timed out — page may be stuck.
    if not timed_out:
        try:
            current_url = page.url
            target_base = domain.replace("www.", "")
            if target_base not in current_url:
                print(f"[!] Browser navigated away to {current_url} — returning to {url}")
                results["notes"].append(f"Browser navigated away to {current_url}; returned to target.")
                try:
                    page.goto(url, timeout=PAGE_LOAD_TIMEOUT, wait_until="domcontentloaded")
                    page.wait_for_timeout(3000)
                except PlaywrightTimeout:
                    pass
        except Exception as e:
            print(f"[!] Domain verification failed: {e}")

    # Take "after" screenshot (attempt even after timeout — may capture partial state).
    after_path = os.path.join(SCREENSHOTS_DIR, f"{safe_domain}_after.png")
    try:
        page.screenshot(path=after_path, full_page=True, timeout=5000)
        results["screenshot_after"] = after_path
        print(f"[*] 'After' screenshot saved: {after_path}")
        report_status("After screenshot captured", 18)
    except Exception as e:
        print(f"[!] Screenshot failed: {e}")

    # Viewport-only screenshot for DevTools evidence composite.
    viewport_path = os.path.join(SCREENSHOTS_DIR, f"{safe_domain}_viewport.png")
    try:
        page.screenshot(path=viewport_path, full_page=False, timeout=5000)
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
    report_status("Results saved to database", 19)

    # Store detailed request metadata for evidence package.
    results["request_details"] = list(request_details_after)

    # ── Clean up ────────────────────────────────────────────────────
    try:
        context.close()
    except Exception:
        pass

    # ── Print summary ─────────────────────────────────────────────
    print_summary(results)
    report_status("Scan complete", 20)

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
    elif results["still_tracking"] == "timeout":
        print(f"\n  *** TIMEOUT — Scan exceeded time limit ***")
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

def _scan_in_process(url, result_queue):
    """Entry point for each scan subprocess. Creates its own browser."""
    try:
        database.init_db()
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            result = scan_url(browser, url)
            browser.close()
        result_queue.put(result)
    except Exception as e:
        result_queue.put({
            "url": url,
            "error": str(e),
            "still_tracking": "unknown",
            "tiktok_trackers_after": [],
        })


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

    # ── Scan each URL in a separate process ──────────────────────────
    # Each URL gets its own process with its own browser. If a scan
    # hangs, process.kill() sends SIGKILL which cannot be caught —
    # kills the process, Playwright, and Chromium instantly.
    all_results = []

    for i, url in enumerate(urls, start=1):
        print(f"\n[{i}/{len(urls)}] Starting scan...")

        result_queue = multiprocessing.Queue()
        scan_process = multiprocessing.Process(
            target=_scan_in_process,
            args=(url, result_queue),
        )
        scan_process.start()
        scan_process.join(timeout=MAX_SCAN_TIME)

        if scan_process.is_alive():
            # Process is still running after 90s — kill it
            print(f"\n[!!!] TIMEOUT ({MAX_SCAN_TIME}s) for {url} — killing scan process")
            scan_process.kill()
            scan_process.join()  # Reap the zombie process
            result = {
                "url": url,
                "still_tracking": "timeout",
                "tiktok_trackers_after": [],
                "trackers_after": [],
                "trackers_before": [],
                "opt_out_found": "unknown",
                "opt_out_clicked": "unknown",
            }
            try:
                database.save_scan_result(
                    url=url,
                    evidence_notes=f"Scan timed out after {MAX_SCAN_TIME}s",
                )
            except Exception:
                pass
            print(f"[*] Skipping to next URL...\n")
        else:
            # Process finished — get the result
            try:
                result = result_queue.get(timeout=5)
            except Exception:
                result = {
                    "url": url,
                    "still_tracking": "unknown",
                    "tiktok_trackers_after": [],
                    "error": "Scan process ended without returning results",
                }

        all_results.append(result)

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
