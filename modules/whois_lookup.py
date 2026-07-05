"""
WHOIS lookup module.

Contains ALL WHOIS logic for the OSINT Reconnaissance Automation Tool.
Flask routes must call `lookup_domain()` from this module rather than
querying python-whois directly.

Fields returned:
    - registrar
    - creation_date
    - expiry_date
    - organization
    - country
    - name_servers

Any field that is missing or cannot be determined is reported as
the string "Not Found". Network/parsing failures are caught and
returned as an "error" key so the route can handle them gracefully.
"""

import whois


NOT_FOUND = "Not Found"


def _normalize(value):
    """
    Convert a raw python-whois field into a clean, display-ready value.

    python-whois fields are inconsistent across registrars: they may
    be None, a single value, or a list of values (sometimes containing
    duplicates or None entries). This normalizes all of that into a
    single readable string, or "Not Found" if nothing usable exists.
    """
    if value is None:
        return NOT_FOUND

    if isinstance(value, (list, tuple, set)):
        cleaned = [str(item).strip() for item in value if item]
        # Remove duplicates while preserving order
        seen = []
        for item in cleaned:
            if item not in seen:
                seen.append(item)
        if not seen:
            return NOT_FOUND
        return ", ".join(seen)

    value_str = str(value).strip()
    return value_str if value_str else NOT_FOUND


def lookup_domain(domain):
    """
    Perform a WHOIS lookup for the given domain.

    Args:
        domain (str): The domain name to look up (e.g. "example.com").

    Returns:
        dict: On success:
            {
                "registrar": str,
                "creation_date": str,
                "expiry_date": str,
                "organization": str,
                "country": str,
                "name_servers": str
            }
            On failure:
            {
                "error": str
            }
    """
    if not domain:
        return {"error": "No domain provided."}

    try:
        record = whois.whois(domain)
    except Exception as exc:
        return {"error": f"WHOIS lookup failed for '{domain}': {exc}"}

    # python-whois returns an object with empty/None attributes
    # (rather than raising) when a domain has no WHOIS record.
    if record is None or not getattr(record, "domain_name", None):
        return {"error": f"No WHOIS data found for '{domain}'."}

    try:
        return {
            "registrar": _normalize(getattr(record, "registrar", None)),
            "creation_date": _normalize(getattr(record, "creation_date", None)),
            "expiry_date": _normalize(getattr(record, "expiration_date", None)),
            "organization": _normalize(getattr(record, "org", None)),
            "country": _normalize(getattr(record, "country", None)),
            "name_servers": _normalize(getattr(record, "name_servers", None)),
        }
    except Exception as exc:
        return {"error": f"Failed to parse WHOIS data for '{domain}': {exc}"}
