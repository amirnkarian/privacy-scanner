"""
evidence.py - Legal evidence package generator for the Privacy Compliance Scanner.

Generates a downloadable ZIP containing:
  - Demand letter template (PDF)
  - Network traffic evidence images
  - Cookie evidence images
  - Full scan report (PDF)
  - Raw evidence log (JSON)
"""

import io
import json
import os
import tempfile
import zipfile
from datetime import datetime
from urllib.parse import urlparse

from fpdf import FPDF
from PIL import Image, ImageDraw, ImageFont


# ────────────────────────────────────────────────────────────────────
# KNOWN TRACKING COOKIE NAMES → PLATFORM MAPPING
# ────────────────────────────────────────────────────────────────────

KNOWN_TRACKING_COOKIES = {
    "_fbp": "Facebook Ads",
    "_fbc": "Facebook Ads",
    "_ttp": "TikTok Ads",
    "_tt_enable_cookie": "TikTok",
    "_pin_unauth": "Pinterest",
    "_pinterest_ct_ua": "Pinterest",
    "_gcl_au": "Google Ads",
    "_gcl_aw": "Google Ads",
    "_ga": "Google Analytics",
    "_gid": "Google Analytics",
    "_gat": "Google Analytics",
    "_ScCbts": "Snapchat",
    "_scid": "Snapchat",
    "_sctr": "Snapchat",
    "_uetsid": "Microsoft Ads",
    "_uetvid": "Microsoft Ads",
    "MR": "Microsoft",
    "MUID": "Microsoft",
    "muc_ads": "Twitter/X Ads",
    "personalization_id": "Twitter/X",
    "_kla_id": "Klaviyo",
    "__kla_id": "Klaviyo",
    "t_pt_gid": "Taboola",
    "_rdt_uuid": "Reddit",
    "clinch-sid": "Clinch",
    "_li_fat_id": "LinkedIn",
    "_clck": "Microsoft Clarity",
    "_clsk": "Microsoft Clarity",
}

# ────────────────────────────────────────────────────────────────────
# TRACKER DOMAIN → CATEGORY MAPPING
# ────────────────────────────────────────────────────────────────────

TRACKER_CATEGORIES = {
    "google-analytics.com": "Google",
    "googletagmanager.com": "Google",
    "doubleclick.net": "Google",
    "googlesyndication.com": "Google",
    "connect.facebook.net": "Meta / Facebook",
    "facebook.net": "Meta / Facebook",
    "graph.facebook.com": "Meta / Facebook",
    "www.facebook.com": "Meta / Facebook",
    "pixel.facebook.com": "Meta / Facebook",
    "clarity.ms": "Microsoft",
    "bat.bing.com": "Microsoft",
    "hotjar.com": "Hotjar",
    "mixpanel.com": "Mixpanel",
    "segment.com": "Segment",
    "amplitude.com": "Amplitude",
    "fullstory.com": "FullStory",
    "crazyegg.com": "Crazy Egg",
    "mouseflow.com": "Mouseflow",
    "hubspot.com": "HubSpot",
    "marketo.com": "Marketo",
    "pardot.com": "Pardot",
    "ct.pinterest.com": "Pinterest",
    "px.ads.linkedin.com": "LinkedIn",
    "snap.licdn.com": "LinkedIn",
    "sc-static.net": "Snapchat",
    "tr.snapchat.com": "Snapchat",
    "us-central1-ct.snap.com": "Snapchat",
    "ads.reddit.com": "Reddit",
    "alb.reddit.com": "Reddit",
    "events.reddit.com": "Reddit",
    "analytics.tiktok.com": "TikTok",
    "business-api.tiktok.com": "TikTok",
    "analytics.twitter.com": "Twitter / X",
    "ads-api.twitter.com": "Twitter / X",
    "t.co": "Twitter / X",
    "criteo.com": "Criteo",
    "criteo.net": "Criteo",
    "taboola.com": "Taboola",
    "outbrain.com": "Outbrain",
    "klaviyo.com": "Klaviyo",
    "attn.tv": "Attentive",
    "attentivemobile.com": "Attentive",
    "tp.media": "Affiliate Tracking",
    "impact.com": "Impact",
    "linksynergy.com": "Rakuten",
    "shareasale.com": "ShareASale",
}


def _get_category_for_domain(domain):
    """Map a request domain to its tracker category."""
    for tracker_domain, category in TRACKER_CATEGORIES.items():
        if tracker_domain in domain:
            return category
    return "Other"


def _sanitize_for_pdf(text):
    """Replace Unicode characters that Helvetica can't render."""
    replacements = {
        "\u2014": "--",   # em dash
        "\u2013": "-",    # en dash
        "\u2018": "'",    # left single quote
        "\u2019": "'",    # right single quote
        "\u201c": '"',    # left double quote
        "\u201d": '"',    # right double quote
        "\u2026": "...",  # ellipsis
        "\u00a0": " ",    # non-breaking space
        "\u2192": "->",   # right arrow
        "\u2190": "<-",   # left arrow
        "\u2194": "<->",  # left-right arrow
        "\u2022": "*",    # bullet
        "\u25cf": "*",    # black circle
        "\u2713": "[x]",  # checkmark
        "\u2717": "[ ]",  # ballot x
        "\u00b7": ".",    # middle dot
    }
    for char, repl in replacements.items():
        text = text.replace(char, repl)
    # Strip any remaining non-latin1 characters.
    return text.encode("latin-1", errors="replace").decode("latin-1")


# ────────────────────────────────────────────────────────────────────
# IMAGE GENERATION — Chrome DevTools Style (Pillow)
# ────────────────────────────────────────────────────────────────────

# Chrome DevTools dark theme colors.
DT_BG = (36, 36, 36)
DT_BG_ALT = (42, 42, 42)
DT_TEXT = (212, 212, 212)
DT_TEXT_DIM = (136, 136, 136)
DT_TEXT_URL = (117, 163, 209)
DT_BORDER = (60, 60, 60)
DT_SELECTED = (37, 63, 98)
DT_TAB_BG = (28, 28, 28)
DT_TAB_ACTIVE = (36, 36, 36)
DT_FILTER_BG = (50, 50, 50)
DT_FILTER_BORDER = (70, 70, 70)
DT_STATUS_BAR_BG = (28, 28, 28)
DT_GREEN = (95, 195, 109)
DT_TAB_UNDERLINE = (59, 130, 246)

# Legacy colors kept for PDF report.
HEADER_BG = (34, 38, 57)


def _load_fonts():
    """Load monospace fonts with cross-platform fallbacks."""
    mono_paths = [
        "/System/Library/Fonts/SFNSMono.ttf",
        "/System/Library/Fonts/Monaco.dfont",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]
    fonts = {}
    for path in mono_paths:
        try:
            fonts["11"] = ImageFont.truetype(path, 11)
            fonts["12"] = ImageFont.truetype(path, 12)
            fonts["13"] = ImageFont.truetype(path, 13)
            fonts["10"] = ImageFont.truetype(path, 10)
            break
        except Exception:
            continue
    if "12" not in fonts:
        default = ImageFont.load_default()
        fonts = {"10": default, "11": default, "12": default, "13": default}
    return fonts


def _count_cookies_for_domain(request_url, cookies):
    """Count cookies that would be sent with a request to this domain."""
    req_domain = urlparse(request_url).netloc
    count = 0
    for cookie in cookies:
        cd = cookie.get("domain", "").lstrip(".")
        if cd in req_domain or req_domain.endswith("." + cd):
            count += 1
    return count


def _format_size(nbytes):
    """Format byte count for display."""
    if nbytes <= 0:
        return "--"
    if nbytes < 1024:
        return f"{nbytes} B"
    return f"{nbytes / 1024:.1f} kB"


def _format_time(timestamp, first_timestamp):
    """Format relative time from first request."""
    delta = timestamp - first_timestamp
    if delta < 0.001:
        return "0 ms"
    if delta < 1.0:
        return f"{int(delta * 1000)} ms"
    return f"{delta:.1f} s"


def _truncate(text, max_chars):
    """Truncate text with ellipsis."""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 2] + ".."


def _draw_devtools_network_panel(tracker_name, requests, cookies_after,
                                  panel_width, panel_height,
                                  total_requests=0):
    """
    Draw a fake Chrome DevTools Network tab panel.
    Returns a PIL Image.
    """
    fonts = _load_fonts()
    img = Image.new("RGB", (panel_width, panel_height), DT_BG)
    draw = ImageDraw.Draw(img)

    # ── Tab bar (28px) ────────────────────────────────────────────
    tab_h = 28
    draw.rectangle([0, 0, panel_width, tab_h], fill=DT_TAB_BG)

    tabs = ["Elements", "Console", "Sources", "Network", "Performance"]
    tx = 8
    for tab in tabs:
        is_active = tab == "Network"
        color = DT_TEXT if is_active else DT_TEXT_DIM
        draw.text((tx, 7), tab, fill=color, font=fonts["12"])
        tw = fonts["12"].getlength(tab) if hasattr(fonts["12"], "getlength") else len(tab) * 7
        if is_active:
            draw.rectangle([tx - 4, 0, tx + tw + 4, tab_h], fill=DT_TAB_ACTIVE)
            draw.text((tx, 7), tab, fill=DT_TEXT, font=fonts["12"])
            draw.rectangle([tx - 4, tab_h - 2, tx + tw + 4, tab_h], fill=DT_TAB_UNDERLINE)
        tx += int(tw) + 20

    # ── Filter bar (32px) ─────────────────────────────────────────
    filter_y = tab_h
    filter_h = 32
    draw.rectangle([0, filter_y, panel_width, filter_y + filter_h], fill=DT_BG)

    # Filter input box.
    fx, fy = 8, filter_y + 5
    fw, fh = min(200, panel_width - 16), 22
    draw.rounded_rectangle([fx, fy, fx + fw, fy + fh], radius=3,
                           fill=DT_FILTER_BG, outline=DT_FILTER_BORDER)
    # Magnifying glass (simple circle + line).
    mx, my = fx + 10, fy + 7
    draw.ellipse([mx, my, mx + 8, my + 8], outline=DT_TEXT_DIM, width=1)
    draw.line([mx + 7, my + 7, mx + 10, my + 10], fill=DT_TEXT_DIM, width=1)
    # Filter text.
    filter_text = tracker_name.lower()
    draw.text((fx + 24, fy + 4), filter_text, fill=DT_TEXT, font=fonts["11"])

    # Type filter buttons.
    type_filters = ["All", "Fetch/XHR", "JS", "CSS", "Img", "Font"]
    bx = fx + fw + 12
    for i, label in enumerate(type_filters):
        color = DT_TEXT if i == 0 else DT_TEXT_DIM
        draw.text((bx, fy + 4), label, fill=color, font=fonts["10"])
        bx += int(fonts["10"].getlength(label) if hasattr(fonts["10"], "getlength") else len(label) * 6) + 10

    # ── Column headers (24px) ─────────────────────────────────────
    hdr_y = filter_y + filter_h
    hdr_h = 24
    draw.rectangle([0, hdr_y, panel_width, hdr_y + hdr_h], fill=DT_BG_ALT)

    # Column layout.
    col_pcts = [0.32, 0.20, 0.10, 0.14, 0.08, 0.08, 0.08]
    col_names = ["Name", "Domain", "Type", "Initiator", "Cookies", "Size", "Time"]
    col_widths = [int(panel_width * p) for p in col_pcts]
    # Adjust last column to fill remaining space.
    col_widths[-1] = panel_width - sum(col_widths[:-1])

    cx = 0
    for i, name in enumerate(col_names):
        draw.text((cx + 6, hdr_y + 5), name, fill=DT_TEXT_DIM, font=fonts["11"])
        cx += col_widths[i]
        if i < len(col_names) - 1:
            draw.line([cx, hdr_y, cx, hdr_y + hdr_h], fill=DT_BORDER, width=1)

    # Bottom border.
    draw.line([0, hdr_y + hdr_h, panel_width, hdr_y + hdr_h], fill=DT_BORDER, width=1)

    # ── Data rows (22px each) ─────────────────────────────────────
    row_h = 22
    data_y = hdr_y + hdr_h
    status_bar_h = 24

    first_ts = requests[0].get("timestamp", 0) if requests else 0
    max_rows = (panel_height - data_y - status_bar_h) // row_h

    for row_idx, req in enumerate(requests[:max_rows]):
        ry = data_y + row_idx * row_h

        # Row background.
        if row_idx == 0:
            bg = DT_SELECTED
        elif row_idx % 2 == 0:
            bg = DT_BG
        else:
            bg = DT_BG_ALT
        draw.rectangle([0, ry, panel_width, ry + row_h], fill=bg)

        # Parse request data.
        parsed = urlparse(req["url"])
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query[:20]
        req_domain = parsed.netloc
        resource_type = req.get("resource_type", "other")
        initiator = urlparse(req.get("headers", {}).get("referer", "")).netloc or "Other"
        cookie_count = _count_cookies_for_domain(req["url"], cookies_after)
        size = _format_size(req.get("post_data_length", 0))
        ts = req.get("timestamp", first_ts)
        time_str = _format_time(ts, first_ts)

        cells = [
            (_truncate(path, col_widths[0] // 7), DT_TEXT_URL),
            (_truncate(req_domain, col_widths[1] // 7), DT_TEXT),
            (_truncate(resource_type, col_widths[2] // 7), DT_TEXT),
            (_truncate(initiator, col_widths[3] // 7), DT_TEXT),
            (str(cookie_count), DT_TEXT),
            (size, DT_TEXT),
            (time_str, DT_TEXT),
        ]

        cx = 0
        for i, (text, color) in enumerate(cells):
            draw.text((cx + 6, ry + 4), text, fill=color, font=fonts["11"])
            cx += col_widths[i]
            if i < len(cells) - 1:
                draw.line([cx, ry, cx, ry + row_h], fill=DT_BORDER, width=1)

        # Row bottom border.
        draw.line([0, ry + row_h, panel_width, ry + row_h], fill=DT_BORDER, width=1)

    # ── Status bar (24px) ─────────────────────────────────────────
    status_y = panel_height - status_bar_h
    draw.rectangle([0, status_y, panel_width, panel_height], fill=DT_STATUS_BAR_BG)
    draw.line([0, status_y, panel_width, status_y], fill=DT_BORDER, width=1)
    if total_requests > 0:
        status_text = f"{len(requests)} / {total_requests} requests"
    else:
        status_text = f"{len(requests)} requests"
    draw.text((8, status_y + 5), status_text,
              fill=DT_TEXT_DIM, font=fonts["11"])

    return img


def _draw_devtools_cookies_panel(tracking_cookies, cookies_after):
    """
    Draw a fake Chrome DevTools Application > Cookies panel.
    Returns a PIL Image.
    """
    fonts = _load_fonts()

    width = 1400
    tab_h = 28
    filter_h = 32
    hdr_h = 24
    row_h = 22
    status_h = 24
    data_rows = min(len(tracking_cookies), 40)
    height = tab_h + filter_h + hdr_h + data_rows * row_h + status_h + 10

    img = Image.new("RGB", (width, height), DT_BG)
    draw = ImageDraw.Draw(img)

    # ── Tab bar ───────────────────────────────────────────────────
    draw.rectangle([0, 0, width, tab_h], fill=DT_TAB_BG)
    tabs = ["Elements", "Console", "Sources", "Network", "Performance", "Application"]
    tx = 8
    for tab in tabs:
        is_active = tab == "Application"
        color = DT_TEXT if is_active else DT_TEXT_DIM
        tw = fonts["12"].getlength(tab) if hasattr(fonts["12"], "getlength") else len(tab) * 7
        if is_active:
            draw.rectangle([tx - 4, 0, tx + tw + 4, tab_h], fill=DT_TAB_ACTIVE)
            draw.text((tx, 7), tab, fill=DT_TEXT, font=fonts["12"])
            draw.rectangle([tx - 4, tab_h - 2, tx + tw + 4, tab_h], fill=DT_TAB_UNDERLINE)
        else:
            draw.text((tx, 7), tab, fill=color, font=fonts["12"])
        tx += int(tw) + 20

    # ── Filter bar ────────────────────────────────────────────────
    fy = tab_h
    draw.rectangle([0, fy, width, fy + filter_h], fill=DT_BG)
    # Sidebar label.
    draw.text((8, fy + 8), "Cookies >", fill=DT_TEXT_DIM, font=fonts["11"])
    # Filter input.
    fx = 100
    draw.rounded_rectangle([fx, fy + 5, fx + 200, fy + 27], radius=3,
                           fill=DT_FILTER_BG, outline=DT_FILTER_BORDER)
    draw.text((fx + 8, fy + 9), "Tracking Cookies", fill=DT_TEXT, font=fonts["11"])

    # ── Column headers ────────────────────────────────────────────
    hy = fy + filter_h
    draw.rectangle([0, hy, width, hy + hdr_h], fill=DT_BG_ALT)

    col_pcts = [0.13, 0.18, 0.17, 0.07, 0.15, 0.07, 0.07, 0.07, 0.09]
    col_names = ["Name", "Value", "Domain", "Path", "Expires", "Size", "HttpOnly", "Secure", "SameSite"]
    col_widths = [int(width * p) for p in col_pcts]
    col_widths[-1] = width - sum(col_widths[:-1])

    cx = 0
    for i, name in enumerate(col_names):
        draw.text((cx + 6, hy + 5), name, fill=DT_TEXT_DIM, font=fonts["11"])
        cx += col_widths[i]
        if i < len(col_names) - 1:
            draw.line([cx, hy, cx, hy + hdr_h], fill=DT_BORDER, width=1)
    draw.line([0, hy + hdr_h, width, hy + hdr_h], fill=DT_BORDER, width=1)

    # ── Data rows ─────────────────────────────────────────────────
    data_y = hy + hdr_h
    for row_idx, cookie in enumerate(tracking_cookies[:40]):
        ry = data_y + row_idx * row_h
        bg = DT_BG if row_idx % 2 == 0 else DT_BG_ALT
        if row_idx == 0:
            bg = DT_SELECTED
        draw.rectangle([0, ry, width, ry + row_h], fill=bg)

        name = cookie.get("name", "")
        value = cookie.get("value", "")
        if len(value) > 15:
            value = value[:12] + "..."
        domain = cookie.get("domain", "")
        path = cookie.get("path", "/")
        expires = cookie.get("expires", -1)
        if expires and expires > 0:
            try:
                exp_str = datetime.fromtimestamp(expires).strftime("%Y-%m-%d %H:%M")
            except Exception:
                exp_str = "Session"
        else:
            exp_str = "Session"
        size_val = len(name) + len(str(cookie.get("value", "")))
        http_only = cookie.get("httpOnly", False)
        secure = cookie.get("secure", False)
        same_site = cookie.get("sameSite", "None")

        cells = [
            (_truncate(name, col_widths[0] // 7), DT_TEXT_URL),
            (_truncate(value, col_widths[1] // 7), DT_TEXT),
            (_truncate(domain, col_widths[2] // 7), DT_TEXT),
            (_truncate(path, col_widths[3] // 7), DT_TEXT),
            (_truncate(exp_str, col_widths[4] // 7), DT_TEXT),
            (str(size_val), DT_TEXT),
            ("✓" if http_only else "", DT_GREEN if http_only else DT_TEXT_DIM),
            ("✓" if secure else "", DT_GREEN if secure else DT_TEXT_DIM),
            (str(same_site), DT_TEXT),
        ]

        cx = 0
        for i, (text, color) in enumerate(cells):
            draw.text((cx + 6, ry + 4), text, fill=color, font=fonts["11"])
            cx += col_widths[i]
            if i < len(cells) - 1:
                draw.line([cx, ry, cx, ry + row_h], fill=DT_BORDER, width=1)
        draw.line([0, ry + row_h, width, ry + row_h], fill=DT_BORDER, width=1)

    # ── Status bar ────────────────────────────────────────────────
    sy = data_y + data_rows * row_h + 5
    draw.rectangle([0, sy, width, height], fill=DT_STATUS_BAR_BG)
    draw.line([0, sy, width, sy], fill=DT_BORDER, width=1)
    draw.text((8, sy + 5),
              f"{len(tracking_cookies)} cookies",
              fill=DT_TEXT_DIM, font=fonts["11"])

    return img


def _generate_devtools_evidence_image(category_name, requests, cookies_after,
                                       viewport_screenshot_path, output_path,
                                       total_requests=0):
    """
    Generate a side-by-side composite: product page (left 50%) + DevTools Network panel (right 50%).
    Width is at least 1920px.
    """
    COMPOSITE_WIDTH = 1920
    LEFT_WIDTH = COMPOSITE_WIDTH // 2   # 960
    RIGHT_WIDTH = COMPOSITE_WIDTH - LEFT_WIDTH  # 960

    # Load and resize the page screenshot for the left half.
    if viewport_screenshot_path and os.path.exists(viewport_screenshot_path):
        page_img = Image.open(viewport_screenshot_path)
        scale = LEFT_WIDTH / page_img.width
        new_height = int(page_img.height * scale)
        page_img = page_img.resize((LEFT_WIDTH, new_height), Image.LANCZOS)
    else:
        new_height = 900
        page_img = Image.new("RGB", (LEFT_WIDTH, new_height), (50, 50, 50))

    panel_height = max(new_height, 600)

    # Draw the DevTools panel for the right half.
    devtools_img = _draw_devtools_network_panel(
        category_name, requests, cookies_after,
        RIGHT_WIDTH, panel_height,
        total_requests=total_requests,
    )

    # Create composite.
    composite = Image.new("RGB", (COMPOSITE_WIDTH, panel_height), DT_BG)
    composite.paste(page_img, (0, 0))

    # Vertical divider.
    cdraw = ImageDraw.Draw(composite)
    cdraw.line([(LEFT_WIDTH, 0), (LEFT_WIDTH, panel_height)], fill=DT_BORDER, width=2)

    composite.paste(devtools_img, (LEFT_WIDTH + 2, 0))
    composite.save(output_path)


def generate_network_evidence_images(result, output_dir):
    """
    Generate DevTools-style composite images per tracker category.
    Returns a list of generated file paths.
    """
    request_details = result.get("request_details", [])
    flagged_domains = result.get("flagged_domains", {})
    cookies_after = result.get("cookies_after_details", [])
    # Prefer product page screenshot; fall back to viewport.
    screenshot_path = result.get("screenshot_product") or result.get("screenshot_viewport")
    total_requests = result.get("total_requests_captured", 0)

    if not request_details or not flagged_domains:
        return []

    # Group flagged requests by category.
    categories = {}
    for req in request_details:
        req_domain = urlparse(req["url"]).netloc
        if req_domain in flagged_domains:
            cat = _get_category_for_domain(req_domain)
            categories.setdefault(cat, []).append(req)

    paths = []
    for category, reqs in sorted(categories.items()):
        safe_cat = category.lower().replace(" / ", "_").replace(" ", "_")
        filename = f"evidence_{safe_cat}.png"
        filepath = os.path.join(output_dir, filename)

        _generate_devtools_evidence_image(
            category, reqs[:50], cookies_after,
            screenshot_path, filepath,
            total_requests=total_requests,
        )
        paths.append(filepath)

    return paths


def generate_cookie_evidence_images(result, output_dir):
    """
    Generate a single DevTools-style cookies evidence image.
    Returns a list with one file path, or empty.
    """
    cookies_after = result.get("cookies_after_details", [])
    if not cookies_after:
        return []

    tracking_cookies = [
        c for c in cookies_after if c.get("name") in KNOWN_TRACKING_COOKIES
    ]
    if not tracking_cookies:
        return []

    filepath = os.path.join(output_dir, "cookies_evidence.png")
    img = _draw_devtools_cookies_panel(tracking_cookies, cookies_after)
    img.save(filepath)
    return [filepath]


def generate_tiktok_evidence_images(result, output_dir):
    """
    Generate TikTok-specific evidence images:
      1. evidence_tiktok_network_[domain].png — side-by-side product page + DevTools Network
      2. evidence_tiktok_cookies_[domain].png — DevTools cookies for TikTok
      3. evidence_product_page_[domain].png  — standalone product page screenshot

    Returns a list of generated file paths.
    """
    domain = urlparse(result["url"]).netloc.replace(":", "_")
    request_details = result.get("request_details", [])
    cookies_after = result.get("cookies_after_details", [])
    screenshot_path = result.get("screenshot_product") or result.get("screenshot_viewport")
    total_requests = result.get("total_requests_captured", 0)
    paths = []

    # TikTok domains to filter for.
    tiktok_domains = [
        "analytics.tiktok.com", "analytics-ipv6.tiktokw.us",
        "business-api.tiktok.com", "www.tiktok.com",
    ]

    # 1. Product page screenshot (standalone copy).
    if screenshot_path and os.path.exists(screenshot_path):
        product_path = os.path.join(output_dir, f"evidence_product_page_{domain}.png")
        with open(screenshot_path, "rb") as f_in:
            with open(product_path, "wb") as f_out:
                f_out.write(f_in.read())
        paths.append(product_path)

    # 2. TikTok network evidence (side-by-side composite).
    tiktok_requests = []
    for req in request_details:
        req_domain = urlparse(req["url"]).netloc
        if any(td in req_domain for td in tiktok_domains):
            tiktok_requests.append(req)

    if tiktok_requests:
        network_path = os.path.join(output_dir, f"evidence_tiktok_network_{domain}.png")
        _generate_devtools_evidence_image(
            "tiktok", tiktok_requests[:50], cookies_after,
            screenshot_path, network_path,
            total_requests=total_requests,
        )
        paths.append(network_path)

    # 3. TikTok cookie evidence.
    tiktok_cookie_names = {"_ttp", "_tt_enable_cookie", "tt_csrf_token",
                           "tt_chain_token", "ttwid", "msToken"}
    tiktok_cookies = [
        c for c in cookies_after
        if c.get("name") in tiktok_cookie_names
        or any(td in c.get("domain", "") for td in ["tiktok", "bytedance"])
    ]
    if tiktok_cookies:
        cookie_path = os.path.join(output_dir, f"evidence_tiktok_cookies_{domain}.png")
        img = _draw_devtools_cookies_panel(tiktok_cookies, cookies_after)
        img.save(cookie_path)
        paths.append(cookie_path)

    return paths


# ────────────────────────────────────────────────────────────────────
# DEMAND LETTER (PDF)
# ────────────────────────────────────────────────────────────────────

def generate_demand_letter(result, output_path):
    """Generate a demand letter template PDF."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    domain = urlparse(result["url"]).netloc
    date_str = datetime.now().strftime("%B %d, %Y")
    flagged = result.get("flagged_domains", {})

    # Group flagged domains by category.
    tracker_groups = {}
    for fd in flagged:
        cat = _get_category_for_domain(fd)
        tracker_groups.setdefault(cat, []).append(fd)

    # Identify tracking cookies.
    tracking_cookies = []
    for cookie in result.get("cookies_after_details", []):
        name = cookie.get("name", "")
        if name in KNOWN_TRACKING_COOKIES:
            tracking_cookies.append((name, KNOWN_TRACKING_COOKIES[name]))

    # ── Disclaimer ────────────────────────────────────────────────
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(180, 0, 0)
    pdf.multi_cell(0, 4, new_x="LMARGIN", new_y="NEXT", text=
        "TEMPLATE DISCLAIMER: This is a template for informational purposes only. "
        "It does not constitute legal advice. Consult a licensed attorney before "
        "sending any legal correspondence. Bracketed items [LIKE THIS] must be "
        "replaced with actual information.")
    pdf.ln(8)
    pdf.set_text_color(0, 0, 0)

    # ── Header ────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "[LAW FIRM NAME]", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, "[Address Line 1]", ln=True)
    pdf.cell(0, 5, "[City, State ZIP]", ln=True)
    pdf.cell(0, 5, "[Phone] | [Email]", ln=True)
    pdf.ln(8)

    # ── Date ──────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, date_str, ln=True)
    pdf.ln(4)

    # ── Recipient ─────────────────────────────────────────────────
    pdf.cell(0, 5, "VIA CERTIFIED MAIL AND EMAIL", ln=True)
    pdf.ln(2)
    pdf.cell(0, 5, "[COMPANY LEGAL NAME]", ln=True)
    pdf.cell(0, 5, "Attn: Legal Department / Privacy Officer", ln=True)
    pdf.cell(0, 5, "[Company Address]", ln=True)
    pdf.cell(0, 5, "[City, State ZIP]", ln=True)
    pdf.ln(6)

    # ── Re: line ──────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 10)
    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        f"Re: {domain}'s Deployment of TikTok Tracking in Violation of "
        "California Privacy Laws - Pre-Litigation Demand")
    pdf.ln(4)

    # ── Body ──────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "", 10)

    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        "Dear Sir or Madam:")
    pdf.ln(3)

    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        "This firm represents [CLIENT NAME] regarding your company's deployment of "
        "TikTok tracking technologies on your website, "
        f"{domain}, in violation of California privacy laws. The purpose of this "
        "letter is to put you on notice of these violations and to demand that you "
        "take immediate corrective action.")
    pdf.ln(3)

    # ── Facts (TikTok-focused) ───────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "FACTUAL BACKGROUND", ln=True)
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)

    opt_out_verified = result.get("opt_out_verified") == "yes"
    opt_out_method = _sanitize_for_pdf(
        result.get("opt_out_method", "the opt-out/reject button")
    )

    # Identify TikTok-specific trackers found.
    tiktok_trackers = result.get("tiktok_trackers_after", [])
    tiktok_domains_str = ", ".join(tiktok_trackers) if tiktok_trackers else "analytics.tiktok.com"

    if opt_out_verified:
        pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
            f"On {date_str}, our client visited {domain}. Upon arrival, the website "
            "presented a cookie consent mechanism. Our client affirmatively opted out "
            f"of tracking via {opt_out_method} on the cookie consent "
            "banner. The opt-out was verified -- the consent banner was confirmed dismissed. "
            "Despite this clear expression of refusal to consent to tracking, "
            "the website continued to transmit user data to TikTok's analytics servers.")
    else:
        pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
            f"On {date_str}, our client visited {domain}. Upon arrival, the website "
            "presented a cookie consent mechanism. Our client attempted to opt out "
            "of tracking by interacting with the cookie consent banner. "
            "Regardless of the opt-out attempt, the website continued to transmit "
            "user data to TikTok's analytics servers during the browsing session.")
    pdf.ln(3)

    # TikTok-specific factual detail.
    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        f"Specifically, after opting out, {domain} continued sending network requests "
        f"to the following TikTok tracking domains: {tiktok_domains_str}. "
        "TikTok's analytics software, commonly deployed as the 'TikTok Pixel,' "
        "collects the following data from each visitor:")
    pdf.ln(2)

    tiktok_data_points = [
        "Device information (type, model, operating system, screen resolution)",
        "Browser fingerprint data (user agent, language, installed plugins)",
        "Geographic location data (derived from IP address)",
        "Full URLs of pages visited on the site",
        "Referral source and search terms used to reach the site",
        "User interaction events (clicks, scrolling, time on page)",
        "Cross-site tracking identifiers via TikTok cookies (_ttp, _tt_enable_cookie)",
    ]
    pdf.set_font("Helvetica", "", 10)
    for point in tiktok_data_points:
        pdf.cell(0, 5, _sanitize_for_pdf(f"  - {point}"), ln=True)
    pdf.ln(3)

    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        "This data is transmitted to TikTok the moment a user visits the site, "
        "even before any consent is given or any interaction occurs. After our client "
        "explicitly opted out, the site continued transmitting this data to TikTok "
        "during subsequent browsing activity, including navigating to product pages "
        "and scrolling through content.")
    pdf.ln(3)

    # NSA / national security context.
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "NATIONAL SECURITY CONCERNS", ln=True)
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)

    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        "The deployment of TikTok tracking on your website raises significant national "
        "security concerns. The National Security Agency (NSA) has publicly described "
        'TikTok as "a platform for surveillance" used for information operations. '
        "TikTok's parent company, ByteDance, is a Chinese corporation subject to "
        "China's National Intelligence Law (2017), which compels Chinese companies to "
        '"support, assist, and cooperate with national intelligence work" and to '
        "provide access to data upon government request.")
    pdf.ln(3)

    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        "By deploying TikTok's analytics pixel on your website, your company is "
        "facilitating the transmission of your customers' browsing data, device "
        "fingerprints, and behavioral patterns to a foreign adversary's data collection "
        "infrastructure. This occurs without meaningful user consent and in direct "
        "contradiction of your users' express opt-out choices.")
    pdf.ln(3)

    # List other trackers for context (informational).
    other_tracker_groups = {cat: doms for cat, doms in tracker_groups.items()
                           if cat.lower() != "tiktok"}
    if other_tracker_groups:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(120, 120, 120)
        pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
            "Note: The following additional tracking platforms were also detected "
            "after opt-out (documented for completeness):")
        pdf.ln(1)
        for category, domains_list in sorted(other_tracker_groups.items()):
            domain_str = ", ".join(sorted(domains_list))
            pdf.cell(0, 5, _sanitize_for_pdf(f"  - {category}: {domain_str}"), ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(3)

    # List TikTok tracking cookies if found.
    tiktok_cookies = [(n, p) for n, p in tracking_cookies
                      if "tiktok" in p.lower()]
    if tiktok_cookies:
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
            "Additionally, the following TikTok tracking cookies were identified "
            "in the browser after the opt-out:")
        pdf.ln(2)
        unique_cookies = sorted(set(tiktok_cookies))
        for name, platform in unique_cookies:
            pdf.cell(0, 5, f"  - {name} ({platform})", ln=True)
        pdf.ln(3)

    # ── Legal violations ──────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "LEGAL VIOLATIONS", ln=True)
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)

    violations = [
        ("California Invasion of Privacy Act (CIPA) - Trap and Trace Device, "
         "Penal Code Sections 631(a) and 638.51",
         "TikTok's analytics software deployed on your website functions as a "
         "trap and trace device under California Penal Code Section 638.51. "
         "It intercepts and records electronic communications including browsing "
         "behavior, device fingerprint data, geographic location, page URLs visited, "
         "referral sources, and user interaction events. Deploying such a device "
         "without explicit user consent violates CIPA Section 631(a). Your website's "
         "continued transmission of user data to TikTok after our client's explicit "
         "opt-out constitutes a per-visit violation. Each individual tracking request "
         f"to {tiktok_domains_str} constitutes a separate violation."),
        ("California Consumer Privacy Act (CCPA/CPRA), Civil Code Section 1798.100 et seq.",
         "Your failure to honor our client's opt-out request violates the CCPA's "
         "requirement to respect consumer choices regarding the sale and sharing of "
         "personal information. Transmitting user data to TikTok -- a foreign-owned "
         "advertising platform -- after opt-out constitutes unauthorized sharing of "
         "personal information for cross-context behavioral advertising in violation "
         "of the CPRA amendments."),
        ("Unfair Competition Law (UCL), Business & Professions Code Section 17200",
         "Deploying TikTok's surveillance infrastructure on a consumer-facing website "
         "while presenting a cookie opt-out mechanism that fails to actually stop "
         "TikTok tracking constitutes unlawful, unfair, and/or fraudulent business "
         "practices."),
        ("False Advertising Law (FAL), Business & Professions Code Section 17500",
         "Representing to consumers that they can opt out of tracking while "
         "continuing to transmit their data to TikTok constitutes false and "
         "misleading advertising."),
        ("Common Law Invasion of Privacy",
         "The continued transmission of our client's browsing activity, device "
         "fingerprint, and behavioral data to TikTok's servers after an explicit "
         "opt-out constitutes an intrusion upon seclusion that would be highly "
         "offensive to a reasonable person, particularly given TikTok's documented "
         "national security risks."),
    ]

    for title, description in violations:
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text= f"- {title}")
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text= f"  {description}")
        pdf.ln(3)

    # ── Demand ────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "DEMAND", ln=True)
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)

    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        "In light of the foregoing, we demand that your company:")
    pdf.ln(2)

    demands = [
        "Immediately remove all TikTok tracking pixels, analytics scripts, and "
        f"related technologies from {domain};",
        "Cease all transmission of user data to TikTok domains (analytics.tiktok.com, "
        "business-api.tiktok.com, and any related endpoints) for users who have "
        "opted out of tracking;",
        "Conduct a comprehensive audit of all tracking technologies deployed on "
        f"{domain}, with particular attention to TikTok integrations and their "
        "compliance with users' opt-out choices;",
        "Provide written confirmation within [14/30] days of receipt of this "
        "letter that the above corrective actions have been taken;",
        "Discuss pre-litigation resolution of our client's claims, including "
        "appropriate compensation for the violations described herein.",
    ]
    for i, demand in enumerate(demands, 1):
        pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text= f"{i}. {demand}")
        pdf.ln(1)
    pdf.ln(3)

    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        "If we do not receive a satisfactory response within [14/30] days, our "
        "client is prepared to pursue all available legal remedies, including but "
        "not limited to statutory damages under CIPA (up to $5,000 per violation), "
        "actual damages, injunctive relief, and attorneys' fees and costs.")
    pdf.ln(6)

    # ── Signature ─────────────────────────────────────────────────
    pdf.cell(0, 5, "Respectfully,", ln=True)
    pdf.ln(10)
    pdf.cell(0, 5, "[ATTORNEY NAME]", ln=True)
    pdf.cell(0, 5, "[BAR NUMBER]", ln=True)
    pdf.cell(0, 5, "[LAW FIRM NAME]", ln=True)
    pdf.ln(8)

    # ── Bottom disclaimer ─────────────────────────────────────────
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(180, 0, 0)
    pdf.multi_cell(0, 4, new_x="LMARGIN", new_y="NEXT", text=
        "TEMPLATE DISCLAIMER: This document is a template generated by an "
        "automated privacy scanning tool. It does not constitute legal advice "
        "and should not be sent without review and modification by a licensed "
        "attorney admitted to practice in the relevant jurisdiction.")

    pdf.output(output_path)


# ────────────────────────────────────────────────────────────────────
# SCAN REPORT (PDF)
# ────────────────────────────────────────────────────────────────────

def generate_scan_report(result, output_path):
    """Generate a comprehensive scan report PDF."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    domain = urlparse(result["url"]).netloc
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    flagged = result.get("flagged_domains", {})

    # ── Title ─────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 15, "Privacy Compliance Scan Report", ln=True, align="C")
    pdf.ln(3)

    # ── URL and date ──────────────────────────────────────────────
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, f"URL: {result['url']}", ln=True)
    pdf.cell(0, 8, f"Date: {date_str}", ln=True)
    pdf.ln(5)

    # ── Executive Summary ─────────────────────────────────────────
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.ln(2)

    if result.get("still_tracking") == "yes":
        pdf.set_fill_color(255, 71, 87)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 12, "  VIOLATION: TikTok tracking continues after user opt-out", ln=True, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)
        pdf.set_font("Helvetica", "", 11)
        opt_method = _sanitize_for_pdf(result.get("opt_out_method", "the cookie consent mechanism"))
        tiktok_after = result.get("tiktok_trackers_after", [])
        tiktok_str = ", ".join(tiktok_after) if tiktok_after else "TikTok domains"
        pdf.multi_cell(0, 6, new_x="LMARGIN", new_y="NEXT", text=
            f"The scan detected TikTok tracking ({tiktok_str}) that continued "
            f"sending data after the user opted out of tracking via {opt_method}. "
            "TikTok's analytics software functions as a trap-and-trace device under "
            "CIPA Section 638.51. This constitutes violations of CIPA, CCPA/CPRA, "
            "and other California privacy laws.")
    elif result.get("still_tracking") == "inconclusive":
        pdf.set_fill_color(255, 165, 2)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 12, "  INCONCLUSIVE: Opt-out could not be verified", ln=True, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)
        pdf.set_font("Helvetica", "", 11)
        pdf.multi_cell(0, 6, new_x="LMARGIN", new_y="NEXT", text=
            "The scanner was unable to verify that the cookie opt-out was successful. "
            "The consent banner may not have been properly dismissed. Trackers were "
            "detected during the browsing session, but it cannot be confirmed whether "
            "these persisted after a valid opt-out. Manual verification is recommended.")
    else:
        pdf.set_fill_color(46, 213, 115)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 12, "  CLEAN: No TikTok tracking after user opt-out", ln=True, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)
        pdf.set_font("Helvetica", "", 11)
        pdf.multi_cell(0, 6, new_x="LMARGIN", new_y="NEXT", text=
            "No TikTok tracker domains were detected after the user opted out. "
            "The website does not appear to transmit data to TikTok after opt-out.")
    pdf.ln(6)

    # ── Scan Details ──────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Scan Details", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Opt-out banner found: {result.get('opt_out_found', 'N/A')}", ln=True)
    pdf.cell(0, 7, f"Opt-out clicked: {result.get('opt_out_clicked', 'N/A')}", ln=True)
    pdf.cell(0, 7, f"Opt-out verified: {result.get('opt_out_verified', 'N/A')}", ln=True)
    opt_method = result.get("opt_out_method")
    if opt_method:
        pdf.cell(0, 7, _sanitize_for_pdf(f"Opt-out method: {opt_method}"), ln=True)
    pdf.cell(0, 7, f"Trackers before opt-out: {len(result.get('trackers_before', []))}", ln=True)
    pdf.cell(0, 7, f"Trackers after opt-out: {len(result.get('trackers_after', []))}", ln=True)
    pdf.cell(0, 7, f"Flagged domains (post-opt-out): {len(flagged)}", ln=True)
    pdf.ln(5)

    # ── Scan Timeline ─────────────────────────────────────────────
    timeline = result.get("scan_timeline", [])
    if timeline:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Scan Timeline", ln=True)
        pdf.ln(2)

        # Table header.
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(34, 38, 57)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(20, 8, "Step", border=1, fill=True, align="C")
        pdf.cell(45, 8, "Timestamp", border=1, fill=True)
        pdf.cell(0, 8, "  Status", border=1, fill=True)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 9)

        for entry in timeline:
            ts = entry.get("timestamp", "")
            if "T" in ts:
                ts = ts.split("T")[1][:8]  # just HH:MM:SS
            pdf.cell(20, 7, str(entry.get("step", "")), border=1, align="C")
            pdf.cell(45, 7, ts, border=1)
            msg = _sanitize_for_pdf(entry.get("message", ""))[:80]
            pdf.cell(0, 7, f"  {msg}", border=1)
            pdf.ln()
        pdf.ln(5)

    # ── Flagged Tracker Domains ───────────────────────────────────
    if flagged:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Flagged Tracker Domains (Post-Opt-Out)", ln=True)
        pdf.ln(2)

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(34, 38, 57)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(70, 8, "  Domain", border=1, fill=True)
        pdf.cell(25, 8, "Requests", border=1, fill=True, align="C")
        pdf.cell(50, 8, "  Category", border=1, fill=True)
        pdf.cell(0, 8, "  Matched Rule", border=1, fill=True)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 9)

        for fd, info in sorted(flagged.items()):
            cat = _get_category_for_domain(fd)
            pdf.cell(70, 7, f"  {fd[:35]}", border=1)
            pdf.cell(25, 7, str(info["count"]), border=1, align="C")
            pdf.cell(50, 7, f"  {cat[:25]}", border=1)
            pdf.cell(0, 7, f"  {info['matched_rule'][:30]}", border=1)
            pdf.ln()
        pdf.ln(5)

    # ── Tracking Cookies ──────────────────────────────────────────
    cookies_after = result.get("cookies_after_details", [])
    tracking_cookies = [
        c for c in cookies_after if c.get("name") in KNOWN_TRACKING_COOKIES
    ]
    if tracking_cookies:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Known Tracking Cookies Found", ln=True)
        pdf.ln(2)

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(34, 38, 57)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(50, 8, "  Name", border=1, fill=True)
        pdf.cell(45, 8, "  Platform", border=1, fill=True)
        pdf.cell(60, 8, "  Domain", border=1, fill=True)
        pdf.cell(0, 8, "  Secure / HttpOnly", border=1, fill=True)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 9)

        for c in tracking_cookies:
            platform = KNOWN_TRACKING_COOKIES.get(c["name"], "")
            flags = []
            if c.get("secure"):
                flags.append("Secure")
            if c.get("httpOnly"):
                flags.append("HttpOnly")
            pdf.cell(50, 7, f"  {c['name'][:25]}", border=1)
            pdf.cell(45, 7, f"  {platform[:22]}", border=1)
            pdf.cell(60, 7, f"  {c.get('domain', '')[:30]}", border=1)
            pdf.cell(0, 7, f"  {', '.join(flags)}", border=1)
            pdf.ln()
        pdf.ln(5)

    # ── Notes ─────────────────────────────────────────────────────
    notes = result.get("notes", [])
    if notes:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, "Notes:", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for note in notes:
            short = _sanitize_for_pdf(note[:200] + "..." if len(note) > 200 else note)
            pdf.multi_cell(0, 6, new_x="LMARGIN", new_y="NEXT", text=f"  - {short}")
        pdf.ln(3)

    # ── Screenshots ───────────────────────────────────────────────
    for label, key in [("Before Opt-Out", "screenshot_before"),
                       ("After Opt-Out", "screenshot_after")]:
        path = result.get(key)
        if path and os.path.exists(path):
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, f"Screenshot: {label}", ln=True)
            pdf.ln(3)
            try:
                pdf.image(path, x=10, w=190)
            except Exception:
                pdf.set_font("Helvetica", "", 11)
                pdf.cell(0, 10, "(Screenshot could not be embedded)", ln=True)

    pdf.output(output_path)


# ────────────────────────────────────────────────────────────────────
# EVIDENCE LOG (JSON)
# ────────────────────────────────────────────────────────────────────

def generate_evidence_log(result, output_path):
    """Dump all scan data as a structured JSON file."""
    log = {
        "scan_url": result.get("url"),
        "scan_date": datetime.now().isoformat(),
        "scan_timeline": result.get("scan_timeline", []),
        "opt_out": {
            "found": result.get("opt_out_found") == "yes",
            "clicked": result.get("opt_out_clicked") == "yes",
            "verified": result.get("opt_out_verified") == "yes",
            "method": result.get("opt_out_method"),
            "attempts": result.get("opt_out_attempts", []),
        },
        "network_requests_after_optout": result.get("request_details", []),
        "cookies_before_optout": result.get("cookies_before_details", []),
        "cookies_after_optout": result.get("cookies_after_details", []),
        "new_cookies_after_optout": result.get("new_cookies_details", []),
        "flagged_tracker_domains": result.get("flagged_domains", {}),
        "trackers_before": result.get("trackers_before", []),
        "trackers_after": result.get("trackers_after", []),
        "tiktok_trackers_after": result.get("tiktok_trackers_after", []),
        "all_request_domains": result.get("all_request_domains", {}),
        "notes": result.get("notes", []),
    }

    with open(output_path, "w") as f:
        json.dump(log, f, indent=2, default=str)


# ────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT — ZIP PACKAGE
# ────────────────────────────────────────────────────────────────────

def generate_evidence_package(result):
    """
    Generate a complete legal evidence package as a ZIP file.

    Args:
        result: The scan results dict from scanner.scan_url().

    Returns:
        ZIP file contents as bytes.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create folder structure.
        letter_dir = os.path.join(tmpdir, "letter")
        screenshots_dir = os.path.join(tmpdir, "screenshots")
        evidence_dir = os.path.join(screenshots_dir, "evidence")
        website_dir = os.path.join(screenshots_dir, "website")
        report_dir = os.path.join(tmpdir, "report")
        raw_dir = os.path.join(tmpdir, "raw_data")

        for d in [letter_dir, evidence_dir, website_dir,
                  report_dir, raw_dir]:
            os.makedirs(d, exist_ok=True)

        # 1. Demand letter.
        generate_demand_letter(result, os.path.join(letter_dir, "demand_letter.pdf"))

        # 2. TikTok-specific evidence images (product page + network + cookies).
        generate_tiktok_evidence_images(result, evidence_dir)

        # 3. Network evidence images per category (DevTools composites).
        generate_network_evidence_images(result, evidence_dir)

        # 4. Cookie evidence image (all tracking cookies).
        generate_cookie_evidence_images(result, evidence_dir)

        # 4. Website screenshots (copy from scan output).
        for key, label in [("screenshot_before", "before"),
                           ("screenshot_after", "after"),
                           ("screenshot_viewport", "viewport"),
                           ("screenshot_product", "product")]:
            src = result.get(key)
            if src and os.path.exists(src):
                domain = urlparse(result["url"]).netloc.replace(":", "_")
                dst = os.path.join(website_dir, f"{domain}_{label}.png")
                with open(src, "rb") as f_in:
                    with open(dst, "wb") as f_out:
                        f_out.write(f_in.read())

        # 5. Scan report.
        generate_scan_report(result, os.path.join(report_dir, "scan_report.pdf"))

        # 6. Evidence log (raw JSON).
        generate_evidence_log(result, os.path.join(raw_dir, "evidence_log.json"))

        # ── Package everything into a ZIP ─────────────────────────
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(tmpdir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, tmpdir)
                    zf.write(file_path, arcname)

        return zip_buffer.getvalue()
