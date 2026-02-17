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
    }
    for char, repl in replacements.items():
        text = text.replace(char, repl)
    # Strip any remaining non-latin1 characters.
    return text.encode("latin-1", errors="replace").decode("latin-1")


# ────────────────────────────────────────────────────────────────────
# IMAGE GENERATION (Pillow)
# ────────────────────────────────────────────────────────────────────

# Colors matching the web UI dark theme.
BG_COLOR = (15, 17, 23)
HEADER_BG = (34, 38, 57)
ROW_ALT = (22, 25, 35)
ROW_NORMAL = (15, 17, 23)
TEXT_COLOR = (220, 220, 230)
HEADER_TEXT = (255, 255, 255)
ACCENT_RED = (255, 71, 87)
ACCENT_PURPLE = (108, 99, 255)
BORDER_COLOR = (50, 55, 75)


def _draw_table_image(title, headers, rows, output_path, col_widths=None):
    """
    Render a data table as a dark-themed PNG image.

    Args:
        title:      Title text shown above the table.
        headers:    List of column header strings.
        rows:       List of lists (each inner list = one row).
        output_path: Where to save the PNG.
        col_widths: Optional list of pixel widths per column.
    """
    try:
        font = ImageFont.truetype("/System/Library/Fonts/SFNSMono.ttf", 14)
        font_bold = ImageFont.truetype("/System/Library/Fonts/SFNSMono.ttf", 14)
        title_font = ImageFont.truetype("/System/Library/Fonts/SFNSMono.ttf", 18)
    except Exception:
        font = ImageFont.load_default()
        font_bold = font
        title_font = font

    row_height = 30
    padding = 12
    title_height = 50

    if col_widths is None:
        col_widths = [max(200, 1200 // len(headers))] * len(headers)

    width = sum(col_widths) + padding * 2
    height = title_height + (len(rows) + 1) * row_height + padding * 2

    img = Image.new("RGB", (width, height), color=BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Title.
    draw.text((padding, 12), title, fill=ACCENT_PURPLE, font=title_font)

    y = title_height

    # Header row.
    draw.rectangle([0, y, width, y + row_height], fill=HEADER_BG)
    x = padding
    for i, header in enumerate(headers):
        draw.text((x, y + 7), header, fill=HEADER_TEXT, font=font_bold)
        x += col_widths[i]
    y += row_height

    # Draw a line under header.
    draw.line([0, y, width, y], fill=BORDER_COLOR, width=1)

    # Data rows.
    for row_idx, row in enumerate(rows):
        bg = ROW_ALT if row_idx % 2 == 0 else ROW_NORMAL
        draw.rectangle([0, y, width, y + row_height], fill=bg)
        x = padding
        for i, cell in enumerate(row):
            cell_str = str(cell)
            # Truncate if too wide.
            max_chars = col_widths[i] // 8
            if len(cell_str) > max_chars:
                cell_str = cell_str[: max_chars - 3] + "..."
            color = TEXT_COLOR
            # Highlight known tracking cookie names in red.
            if i == 0 and cell_str in KNOWN_TRACKING_COOKIES:
                color = ACCENT_RED
            draw.text((x, y + 7), cell_str, fill=color, font=font)
            x += col_widths[i]
        y += row_height

    img.save(output_path)


def generate_network_evidence_images(result, output_dir):
    """
    Generate table images grouping flagged network requests by tracker category.

    Returns a list of generated file paths.
    """
    request_details = result.get("request_details", [])
    flagged_domains = result.get("flagged_domains", {})

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
    for category, requests in sorted(categories.items()):
        safe_cat = category.lower().replace(" / ", "_").replace(" ", "_")
        filename = f"network_{safe_cat}.png"
        filepath = os.path.join(output_dir, filename)

        headers = ["Request URL", "Domain", "Method", "Type"]
        rows = []
        for req in requests[:50]:  # cap at 50 rows per image
            req_domain = urlparse(req["url"]).netloc
            rows.append([
                req["url"],
                req_domain,
                req["method"],
                req["resource_type"],
            ])

        col_widths = [550, 280, 80, 120]
        _draw_table_image(
            f"Network Evidence: {category} ({len(requests)} requests)",
            headers, rows, filepath, col_widths,
        )
        paths.append(filepath)

    return paths


def generate_cookie_evidence_images(result, output_dir):
    """
    Generate table images showing tracking cookies grouped by domain.

    Returns a list of generated file paths.
    """
    cookies_after = result.get("cookies_after_details", [])
    if not cookies_after:
        return []

    # Group cookies by domain, only include domains with known tracking cookies.
    domains = {}
    for cookie in cookies_after:
        name = cookie.get("name", "")
        if name in KNOWN_TRACKING_COOKIES:
            domain = cookie.get("domain", "unknown")
            domains.setdefault(domain, []).append(cookie)

    paths = []
    for domain, cookies in sorted(domains.items()):
        safe_domain = domain.lstrip(".").replace(".", "_").replace(":", "_")
        filename = f"cookies_{safe_domain}.png"
        filepath = os.path.join(output_dir, filename)

        headers = ["Name", "Platform", "Value", "Domain", "HttpOnly", "Secure"]
        rows = []
        for c in cookies:
            platform = KNOWN_TRACKING_COOKIES.get(c["name"], "")
            value = str(c.get("value", ""))
            if len(value) > 20:
                value = value[:17] + "..."
            rows.append([
                c["name"],
                platform,
                value,
                c.get("domain", ""),
                "Yes" if c.get("httpOnly") else "No",
                "Yes" if c.get("secure") else "No",
            ])

        col_widths = [180, 160, 200, 250, 80, 80]
        _draw_table_image(
            f"Cookie Evidence: {domain}",
            headers, rows, filepath, col_widths,
        )
        paths.append(filepath)

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
        f"Re: {domain}'s Violations of California Privacy Laws "
        "- Pre-Litigation Demand")
    pdf.ln(4)

    # ── Body ──────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "", 10)

    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        "Dear Sir or Madam:")
    pdf.ln(3)

    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        "This firm represents [CLIENT NAME] regarding your company's violations of "
        "California privacy laws in connection with the operation of your website, "
        f"{domain}. The purpose of this letter is to put you on notice of these "
        "violations and to demand that you take immediate corrective action.")
    pdf.ln(3)

    # ── Facts ─────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "FACTUAL BACKGROUND", ln=True)
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)

    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        f"On {date_str}, our client visited {domain}. Upon arrival, the website "
        "presented a cookie consent mechanism. Our client affirmatively opted out "
        "of tracking by clicking the opt-out/reject button on the cookie consent "
        "banner. Despite this clear expression of refusal to consent to tracking, "
        "the website continued to deploy tracking technologies.")
    pdf.ln(3)

    pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
        "Specifically, after opting out, the following tracking platforms continued "
        "to receive data from your website during normal browsing activity:")
    pdf.ln(2)

    # List tracker platforms.
    for category, domains_list in sorted(tracker_groups.items()):
        domain_str = ", ".join(sorted(domains_list))
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text= f"- {category}")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text= f"    Domains: {domain_str}")
        pdf.ln(1)
    pdf.ln(2)

    # List tracking cookies if found.
    if tracking_cookies:
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 5, new_x="LMARGIN", new_y="NEXT", text=
            "Additionally, the following tracking cookies were identified "
            "in the browser after the opt-out:")
        pdf.ln(2)
        unique_cookies = sorted(set(tracking_cookies))
        for name, platform in unique_cookies:
            pdf.cell(0, 5, f"  - {name} ({platform})", ln=True)
        pdf.ln(3)

    # ── Legal violations ──────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "LEGAL VIOLATIONS", ln=True)
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)

    violations = [
        ("California Invasion of Privacy Act (CIPA), Penal Code Sections 631 and 635",
         "Your website's continued deployment of tracking technologies after our "
         "client's opt-out constitutes unauthorized interception and recording of "
         "electronic communications. Each individual tracking request constitutes "
         "a separate violation."),
        ("California Consumer Privacy Act (CCPA/CPRA), Civil Code Section 1798.100 et seq.",
         "Your failure to honor our client's opt-out request violates the CCPA's "
         "requirement to respect consumer choices regarding the sale and sharing of "
         "personal information. Under the CPRA amendments, consumers have the right "
         "to opt out of cross-context behavioral advertising."),
        ("Unfair Competition Law (UCL), Business & Professions Code Section 17200",
         "The above-described conduct constitutes unlawful, unfair, and/or "
         "fraudulent business practices."),
        ("False Advertising Law (FAL), Business & Professions Code Section 17500",
         "Representing to consumers that they can opt out of tracking while "
         "continuing to track constitutes false and misleading advertising."),
        ("Common Law Invasion of Privacy",
         "The continued tracking of our client's browsing activity after an "
         "explicit opt-out constitutes an intrusion upon seclusion."),
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
        "Immediately cease all tracking of users who have opted out of tracking "
        "via your cookie consent mechanism;",
        "Conduct a comprehensive audit of all tracking technologies deployed on "
        f"{domain} to ensure compliance with users' opt-out choices;",
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
        pdf.cell(0, 12, "  VIOLATION: Tracking continues after user opt-out", ln=True, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)
        pdf.set_font("Helvetica", "", 11)
        pdf.multi_cell(0, 6, new_x="LMARGIN", new_y="NEXT", text=
            f"The scan detected {len(flagged)} tracker domain(s) that continued "
            f"sending data after the user opted out of tracking via the cookie "
            f"consent mechanism. This may constitute violations of CIPA, CCPA/CPRA, "
            f"and other California privacy laws.")
    else:
        pdf.set_fill_color(46, 213, 115)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 12, "  CLEAN: Tracking stopped after user opt-out", ln=True, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)
        pdf.set_font("Helvetica", "", 11)
        pdf.multi_cell(0, 6, new_x="LMARGIN", new_y="NEXT", text=
            "No known tracker domains were detected after the user opted out. "
            "The website appears to respect the user's opt-out choice.")
    pdf.ln(6)

    # ── Scan Details ──────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Scan Details", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Opt-out banner found: {result.get('opt_out_found', 'N/A')}", ln=True)
    pdf.cell(0, 7, f"Opt-out clicked: {result.get('opt_out_clicked', 'N/A')}", ln=True)
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
        },
        "network_requests_after_optout": result.get("request_details", []),
        "cookies_before_optout": result.get("cookies_before_details", []),
        "cookies_after_optout": result.get("cookies_after_details", []),
        "new_cookies_after_optout": result.get("new_cookies_details", []),
        "flagged_tracker_domains": result.get("flagged_domains", {}),
        "trackers_before": result.get("trackers_before", []),
        "trackers_after": result.get("trackers_after", []),
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
        network_dir = os.path.join(screenshots_dir, "network")
        cookies_dir = os.path.join(screenshots_dir, "cookies")
        website_dir = os.path.join(screenshots_dir, "website")
        report_dir = os.path.join(tmpdir, "report")
        raw_dir = os.path.join(tmpdir, "raw_data")

        for d in [letter_dir, network_dir, cookies_dir, website_dir,
                  report_dir, raw_dir]:
            os.makedirs(d, exist_ok=True)

        # 1. Demand letter.
        generate_demand_letter(result, os.path.join(letter_dir, "demand_letter.pdf"))

        # 2. Network evidence images.
        generate_network_evidence_images(result, network_dir)

        # 3. Cookie evidence images.
        generate_cookie_evidence_images(result, cookies_dir)

        # 4. Website screenshots (copy from scan output).
        for key, label in [("screenshot_before", "before"),
                           ("screenshot_after", "after")]:
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
