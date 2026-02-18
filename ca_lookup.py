"""
ca_lookup.py - California Secretary of State business registration lookup.

Searches bizfileonline.sos.ca.gov for company registrations based on domain names.
Used to strengthen legal claims in privacy violation cases by identifying the
legal entity, registration status, and registered agent for service of process.
"""

import re
import time
from urllib.parse import urlparse

from playwright.sync_api import TimeoutError as PlaywrightTimeout


# In-memory cache: {domain: result_dict}
_ca_cache = {}

# Common domain prefixes that are not part of the company name.
_STRIP_PREFIXES = [
    "drink", "get", "shop", "buy", "try", "use", "my", "the", "go",
    "visit", "hello", "join", "meet", "wear", "eat",
]

# SOS search URL
_SOS_SEARCH_URL = "https://bizfileonline.sos.ca.gov/search/business"


def _extract_company_name(domain):
    """
    Extract likely company name candidates from a domain.

    e.g. drinkag1.com  -> ["AG1", "drinkag1", "AG1 Inc", "AG1 LLC"]
         hottopic.com  -> ["Hot Topic", "hottopic", "Hot Topic Inc", "Hot Topic LLC"]
         kos.com       -> ["KOS", "kos", "KOS Inc", "KOS LLC"]

    Strategy:
      1. Strip www. and TLD
      2. Remove common prefixes (drink, get, shop, buy, try, use, my, the, go)
      3. Split on hyphens/camelCase, capitalize
      4. Generate variations: base, base + " Inc", base + " LLC", base + " USA"
    """
    # Strip scheme and get netloc.
    if "://" in domain:
        domain = urlparse(domain).netloc
    # Remove www. and TLD.
    name = domain.split(".")[0].lower()
    if name.startswith("www"):
        parts = domain.split(".")
        name = parts[1] if len(parts) > 2 else parts[0]
        name = name.lower()

    candidates = []

    # Try stripping known prefixes to get the core name.
    stripped = name
    for prefix in _STRIP_PREFIXES:
        if name.startswith(prefix) and len(name) > len(prefix):
            stripped = name[len(prefix):]
            break

    # Split on hyphens.
    parts = stripped.split("-")

    # Also try splitting camelCase (e.g. "hotTopic" -> ["hot", "topic"]).
    camel_parts = re.sub(r"([a-z])([A-Z])", r"\1 \2", stripped).split()
    if len(camel_parts) > 1:
        parts = camel_parts

    # Build the "nice" name: capitalize each part.
    nice_name = " ".join(p.capitalize() for p in parts)

    # If the stripped name is different from the original, prioritize it.
    if stripped != name:
        candidates.append(stripped.upper())
        candidates.append(nice_name)

    # Add the full domain-based name.
    full_nice = " ".join(p.capitalize() for p in name.split("-"))
    if full_nice not in candidates:
        candidates.append(full_nice)

    # Add raw name (lowercase).
    if name not in candidates:
        candidates.append(name)

    # Add suffix variations for each unique base.
    bases = list(dict.fromkeys(candidates))  # dedupe preserving order
    for base in bases:
        for suffix in [" Inc", " LLC", " USA"]:
            variation = base + suffix
            if variation not in candidates:
                candidates.append(variation)

    return candidates


def _find_legal_name_on_site(page):
    """
    Check the website's footer for a legal entity name.
    Look for patterns like "(c) 2024 Company Name, Inc." or
    "Company Name LLC" in footer text.

    Returns list of candidate names.
    """
    candidates = []
    try:
        # Try to find footer text.
        footer_text = ""
        for selector in ["footer", "[class*='footer']", "[id*='footer']"]:
            try:
                el = page.query_selector(selector)
                if el:
                    text = el.inner_text()
                    if text:
                        footer_text += " " + text
            except Exception:
                continue

        if not footer_text:
            return candidates

        # Look for copyright patterns: "© 2024 Company Name, Inc."
        copyright_patterns = [
            r"(?:©|\(c\)|copyright)\s*\d{4}\s+([A-Z][A-Za-z0-9\s&]+(?:,?\s*(?:Inc|LLC|Corp|Ltd|L\.L\.C|Co)\.?))",
            r"(?:©|\(c\)|copyright)\s*\d{4}\s+([A-Z][A-Za-z0-9\s&]{2,40})",
        ]

        for pattern in copyright_patterns:
            matches = re.findall(pattern, footer_text, re.IGNORECASE)
            for match in matches:
                clean = match.strip().rstrip(".")
                if len(clean) > 2 and clean not in candidates:
                    candidates.append(clean)

    except Exception:
        pass

    return candidates


def _scrape_ca_sos(browser, search_terms):
    """
    Use Playwright to search bizfileonline.sos.ca.gov/search/business.

    For each search term:
      1. Navigate to search page
      2. Type company name into search input
      3. Click Search
      4. Wait for results
      5. Parse result rows: entity name, number, status, formation date, entity type
      6. If results found, click best match to get detail page
      7. On detail page: extract registered agent name + address

    Returns: {
        "status": "found" | "not_found" | "inconclusive" | "error",
        "entity_name": str,
        "entity_number": str,
        "entity_status": str,  # "Active", "Suspended", etc.
        "entity_type": str,    # "Corporation", "LLC", etc.
        "formation_date": str,
        "registered_agent": str,
        "agent_address": str,
        "search_term_used": str,
    }
    """
    context = None
    try:
        context = browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()

        for search_term in search_terms:
            try:
                # Navigate to SOS search page.
                page.goto(_SOS_SEARCH_URL, timeout=30000, wait_until="networkidle")
                page.wait_for_timeout(2000)

                # Find and fill the search input.
                search_input = page.query_selector(
                    'input[id="SearchCriteria"], '
                    'input[name="SearchCriteria"], '
                    'input[type="text"][class*="search"], '
                    'input[type="text"]'
                )
                if not search_input:
                    # Try broader selector.
                    search_input = page.locator('input[type="text"]').first
                    if not search_input:
                        continue

                search_input.fill("")
                search_input.fill(search_term)
                page.wait_for_timeout(500)

                # Click the search button.
                search_btn = page.query_selector(
                    'button[type="submit"], '
                    'input[type="submit"], '
                    'button:has-text("Search"), '
                    'a:has-text("Search")'
                )
                if search_btn:
                    search_btn.click()
                else:
                    search_input.press("Enter")

                # Wait for results to load.
                try:
                    page.wait_for_load_state("networkidle", timeout=30000)
                except PlaywrightTimeout:
                    pass
                page.wait_for_timeout(3000)

                # Parse result rows from the table.
                results = _parse_search_results(page, search_term)

                if results and results["status"] == "found":
                    # Try to get detail page info.
                    detail = _get_entity_details(page, results)
                    if detail:
                        results.update(detail)
                    return results

                # Delay between searches to avoid hammering the site.
                time.sleep(3)

            except PlaywrightTimeout:
                continue
            except Exception:
                continue

        return {
            "status": "not_found",
            "entity_name": None,
            "entity_number": None,
            "entity_status": None,
            "entity_type": None,
            "formation_date": None,
            "registered_agent": None,
            "agent_address": None,
            "search_term_used": search_terms[0] if search_terms else None,
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "entity_name": None,
            "entity_number": None,
            "entity_status": None,
            "entity_type": None,
            "formation_date": None,
            "registered_agent": None,
            "agent_address": None,
            "search_term_used": None,
        }
    finally:
        if context:
            try:
                context.close()
            except Exception:
                pass


def _parse_search_results(page, search_term):
    """
    Parse the SOS search results page for matching entities.
    Returns a result dict or None.
    """
    try:
        # Look for result rows in a table or list.
        rows = page.query_selector_all(
            'table tbody tr, '
            '.search-results tr, '
            '[class*="result"] tr, '
            '.table tbody tr'
        )

        if not rows:
            # Check for "no results" message.
            page_text = page.inner_text("body")
            if "no results" in page_text.lower() or "no records" in page_text.lower():
                return {"status": "not_found"}
            return None

        best_match = None
        active_matches = []
        all_matches = []

        for row in rows[:20]:  # Limit to first 20 rows
            try:
                cells = row.query_selector_all("td")
                if len(cells) < 3:
                    continue

                cell_texts = []
                for cell in cells:
                    text = cell.inner_text().strip()
                    cell_texts.append(text)

                # Try to identify columns: typically entity name, number, status, type
                entity_info = _extract_entity_from_row(cell_texts)
                if entity_info:
                    all_matches.append(entity_info)
                    if entity_info.get("entity_status", "").lower() == "active":
                        active_matches.append(entity_info)

            except Exception:
                continue

        if active_matches:
            # Prefer the best name match among active entities.
            best = _best_name_match(active_matches, search_term)
            return {
                "status": "found",
                "search_term_used": search_term,
                **best,
            }
        elif all_matches:
            best = _best_name_match(all_matches, search_term)
            status = best.get("entity_status", "").lower()
            if status and status != "active":
                return {
                    "status": "inconclusive",
                    "search_term_used": search_term,
                    **best,
                }
            return {
                "status": "found",
                "search_term_used": search_term,
                **best,
            }

        return {"status": "not_found"}

    except Exception:
        return None


def _extract_entity_from_row(cell_texts):
    """
    Given a list of cell texts from a table row, try to extract
    entity name, number, status, and type.
    """
    if len(cell_texts) < 2:
        return None

    entity = {
        "entity_name": None,
        "entity_number": None,
        "entity_status": None,
        "entity_type": None,
        "formation_date": None,
        "registered_agent": None,
        "agent_address": None,
    }

    for text in cell_texts:
        text_lower = text.lower().strip()

        # Entity number: typically starts with C or has digits.
        if re.match(r"^[A-Z]?\d{6,12}$", text.strip()):
            entity["entity_number"] = text.strip()

        # Status: Active, Suspended, Dissolved, etc.
        elif text_lower in ("active", "suspended", "dissolved", "canceled",
                            "forfeited", "surrendered", "merged", "converted"):
            entity["entity_status"] = text.strip()

        # Entity type.
        elif text_lower in ("corporation", "llc", "limited liability company",
                            "limited partnership", "general partnership",
                            "corporation - domestic - stock",
                            "corporation - domestic - nonprofit"):
            entity["entity_type"] = text.strip()
        elif "corporation" in text_lower or "llc" in text_lower or "limited" in text_lower:
            entity["entity_type"] = text.strip()

        # Date pattern.
        elif re.match(r"\d{1,2}/\d{1,2}/\d{4}", text.strip()):
            entity["formation_date"] = text.strip()

    # The first non-matched substantial text is likely the entity name.
    for text in cell_texts:
        text = text.strip()
        if (text and len(text) > 2
                and text != entity["entity_number"]
                and text != entity["entity_status"]
                and text != entity["entity_type"]
                and text != entity["formation_date"]
                and not re.match(r"^[A-Z]?\d{6,12}$", text)):
            entity["entity_name"] = text
            break

    # Must have at least a name to be useful.
    if not entity["entity_name"]:
        return None

    return entity


def _best_name_match(matches, search_term):
    """Pick the best matching entity from a list based on the search term."""
    search_lower = search_term.lower().strip()

    # Score each match.
    scored = []
    for match in matches:
        name = (match.get("entity_name") or "").lower()
        score = 0

        # Exact match is best.
        if search_lower == name:
            score = 100
        # Name starts with the search term.
        elif name.startswith(search_lower):
            score = 80
        # Search term is contained in the name.
        elif search_lower in name:
            score = 60
        # Name contains part of the search term.
        elif any(word in name for word in search_lower.split()):
            score = 40
        else:
            score = 10

        # Bonus for active status.
        if (match.get("entity_status") or "").lower() == "active":
            score += 5

        scored.append((score, match))

    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[0][1] if scored else matches[0]


def _get_entity_details(page, result):
    """
    Try to click on the entity row to get to the detail page and
    extract registered agent information.
    """
    try:
        entity_name = result.get("entity_name", "")
        if not entity_name:
            return None

        # Try to click on a link containing the entity name.
        link = page.query_selector(f'a:has-text("{entity_name}")')
        if not link:
            # Try partial match.
            links = page.query_selector_all("a")
            for l in links:
                try:
                    text = l.inner_text().strip()
                    if entity_name.lower() in text.lower():
                        link = l
                        break
                except Exception:
                    continue

        if not link:
            return None

        link.click()

        try:
            page.wait_for_load_state("networkidle", timeout=30000)
        except PlaywrightTimeout:
            pass
        page.wait_for_timeout(3000)

        # Extract details from the detail page.
        detail = {}
        page_text = page.inner_text("body")

        # Look for registered agent info.
        agent_patterns = [
            r"Agent\s+(?:for\s+)?Service\s+of\s+Process[:\s]*([^\n]+)",
            r"Registered\s+Agent[:\s]*([^\n]+)",
        ]
        for pattern in agent_patterns:
            match = re.search(pattern, page_text, re.IGNORECASE)
            if match:
                detail["registered_agent"] = match.group(1).strip()
                break

        # Look for agent address.
        address_patterns = [
            r"Agent\s+Address[:\s]*([^\n]+(?:\n[^\n]+)?)",
            r"(?:Agent|Service)\s+(?:of\s+Process\s+)?Address[:\s]*([^\n]+)",
        ]
        for pattern in address_patterns:
            match = re.search(pattern, page_text, re.IGNORECASE)
            if match:
                detail["agent_address"] = match.group(1).strip()
                break

        # Try to extract entity type and formation date from detail page
        # if not already found.
        if not result.get("entity_type"):
            type_match = re.search(
                r"Entity\s+Type[:\s]*([^\n]+)", page_text, re.IGNORECASE
            )
            if type_match:
                detail["entity_type"] = type_match.group(1).strip()

        if not result.get("formation_date"):
            date_match = re.search(
                r"(?:Formation|Registration)\s+Date[:\s]*([^\n]+)",
                page_text, re.IGNORECASE,
            )
            if date_match:
                detail["formation_date"] = date_match.group(1).strip()

        if not result.get("entity_status"):
            status_match = re.search(
                r"Status[:\s]*([^\n]+)", page_text, re.IGNORECASE
            )
            if status_match:
                detail["entity_status"] = status_match.group(1).strip()

        return detail if detail else None

    except Exception:
        return None


def lookup_ca_registration(browser, domain, page=None):
    """
    Main entry point. Checks cache first.

    1. Extract company name candidates from domain
    2. Optionally check the site footer for legal name (if page provided)
    3. For each candidate, search CA SOS
    4. If "Active" match found, return it
    5. If multiple matches or suspended, return "inconclusive"
    6. If no match after all candidates, return "not_found"
    7. Cache and return result

    Args:
        browser: Playwright Browser instance.
        domain: The domain being scanned (e.g. "drinkag1.com").
        page: Optional Playwright Page object to check footer for legal name.

    Returns:
        Dict with registration info or status.
    """
    # Normalize domain.
    if "://" in domain:
        domain = urlparse(domain).netloc
    domain = domain.lower().replace("www.", "")

    # Check cache.
    if domain in _ca_cache:
        return _ca_cache[domain]

    print(f"[*] Looking up CA business registration for {domain}...")

    # Step 1: Extract company name candidates from domain.
    candidates = _extract_company_name(domain)

    # Step 2: Optionally check the site footer for legal name.
    if page:
        try:
            footer_names = _find_legal_name_on_site(page)
            if footer_names:
                # Prepend footer names as they're more likely to be accurate.
                candidates = footer_names + candidates
                print(f"[*] Found potential legal names in footer: {footer_names}")
        except Exception:
            pass

    # Deduplicate while preserving order.
    seen = set()
    unique_candidates = []
    for c in candidates:
        c_lower = c.lower().strip()
        if c_lower not in seen and len(c_lower) > 1:
            seen.add(c_lower)
            unique_candidates.append(c)

    print(f"[*] CA SOS search candidates: {unique_candidates[:6]}")

    # Step 3: Search CA SOS.
    result = _scrape_ca_sos(browser, unique_candidates[:6])  # Limit to 6 candidates

    # Step 4-6: Result is already categorized by _scrape_ca_sos.

    # Step 7: Cache and return.
    _ca_cache[domain] = result

    status = result.get("status", "error")
    if status == "found":
        print(f"[*] CA registration FOUND: {result.get('entity_name')} "
              f"(#{result.get('entity_number')}, {result.get('entity_status')})")
    elif status == "not_found":
        print(f"[*] CA registration NOT FOUND for {domain}")
    elif status == "inconclusive":
        print(f"[*] CA registration INCONCLUSIVE for {domain}: "
              f"{result.get('entity_name')} ({result.get('entity_status')})")
    else:
        print(f"[*] CA registration lookup ERROR for {domain}: "
              f"{result.get('message', 'unknown error')}")

    return result
