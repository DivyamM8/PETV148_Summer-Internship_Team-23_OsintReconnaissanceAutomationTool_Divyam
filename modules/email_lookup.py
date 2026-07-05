"""
Email harvesting module.

Contains ALL email harvesting logic for the OSINT Reconnaissance
Automation Tool. Emails are harvested passively by fetching the
target domain's public webpage(s) with `requests` and extracting any
email addresses present in the page content — no active scanning or
authentication is performed.

Known placeholder/template addresses (e.g. "you@domain.com",
"example@example.com") are filtered out, since these are almost
always leftover boilerplate rather than real contact addresses.
Duplicates are removed automatically.

Flask routes must call `harvest_emails()` from this module.
"""

import re
import requests

REQUEST_TIMEOUT = 10
REQUEST_HEADERS = {"User-Agent": "OSINT-Recon-Tool/1.0"}

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Pages are tried in order; the first one that responds successfully
# is used to search for email addresses.
CANDIDATE_URLS = [
    "https://{domain}",
    "https://www.{domain}",
    "http://{domain}",
]

# Exact placeholder addresses commonly left over from website
# templates/boilerplate, which are not real contact addresses.
PLACEHOLDER_EMAILS = {
    "you@domain.com",
    "example@example.com",
    "admin@example.com",
    "test@test.com",
}

# Entire placeholder domains: any address ending in one of these is
# filtered out regardless of the local part (e.g. "sales@example.com",
# "info@domain.com" are just as bogus as the exact matches above).
PLACEHOLDER_DOMAINS = {
    "domain.com",
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "yourdomain.com",
    "email.com",
    "yourcompany.com",
}


def _log(message):
    """Log technical details to the terminal only (never shown to the user)."""
    print(f"[Email Module] {message}")


def _is_placeholder(email):
    """Return True if an email is a known placeholder/boilerplate address."""
    if email in PLACEHOLDER_EMAILS:
        return True
    domain_part = email.rsplit("@", 1)[-1]
    return domain_part in PLACEHOLDER_DOMAINS


def _fetch_page(url):
    """Fetch a URL's HTML content, returning None on any failure."""
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as exc:
        _log(f"Could not fetch '{url}': {exc}")
        return None


def harvest_emails(domain):
    """
    Passively harvest email addresses found on a domain's public
    homepage, filtering out placeholder/boilerplate addresses and
    duplicates.

    Args:
        domain (str): The domain to search (e.g. "example.com").

    Returns:
        dict: On success:
            {
                "emails": list[str]   # empty list if none found
            }
            On failure (target unreachable on every candidate URL):
            {
                "error": str
            }
    """
    if not domain:
        return {"error": "No domain provided."}

    emails = set()
    reached_target = False

    for url_template in CANDIDATE_URLS:
        url = url_template.format(domain=domain)
        html = _fetch_page(url)

        if html is None:
            continue

        reached_target = True
        for match in EMAIL_REGEX.findall(html):
            emails.add(match.lower())

        if emails:
            break

    if not reached_target:
        _log(f"Could not reach any candidate URL for '{domain}' to harvest emails.")
        return {"error": f"Could not reach '{domain}' to harvest emails."}

    # Remove known placeholder/boilerplate addresses; duplicates are
    # already impossible since `emails` is a set.
    filtered_emails = {email for email in emails if not _is_placeholder(email)}

    removed_count = len(emails) - len(filtered_emails)
    if removed_count:
        _log(f"Filtered out {removed_count} placeholder email(s) for '{domain}'.")

    # Handled gracefully: an empty list is a valid, non-error result.
    return {"emails": sorted(filtered_emails)}
