"""
Input validation/normalization utilities.

Contains `normalize_domain()`, the single source of truth for turning
whatever a user types into the domain form (bare domain, full URL,
with/without "www.", with/without a trailing slash, extra
whitespace, mixed case, etc.) into one canonical form.

Every route must normalize a domain with this function before
passing it to any reconnaissance module, so every module always
receives the same canonical value for the same underlying domain.
"""

import re
from urllib.parse import urlparse

# Matches a URL scheme prefix, e.g. "http://", "https://", "ftp://".
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def normalize_domain(raw_domain):
    """
    Normalize raw user input into a canonical bare domain.

    Examples (all normalize to "google.com"):
        "google.com"
        "www.google.com"
        "http://google.com"
        "https://google.com"
        "https://www.google.com/"
        "  https://WWW.Google.com/  "

    Args:
        raw_domain (str): Raw domain/URL input from the user.

    Returns:
        str: The normalized domain (lowercase, no scheme, no "www.",
        no port, no path, no trailing slash), or "" if the input is
        empty/blank.
    """
    if not raw_domain:
        return ""

    value = raw_domain.strip()
    if not value:
        return ""

    # If there's no scheme, prefix "//" so urlparse still treats the
    # input as netloc (host[:port]) rather than as a relative path.
    parseable = value if _SCHEME_RE.match(value) else f"//{value}"
    parsed = urlparse(parseable)
    host = parsed.netloc or parsed.path

    # Drop a port (e.g. "example.com:8080") and any stray path/query
    # fragment that slipped through (e.g. "example.com/path?x=1").
    host = host.split(":", 1)[0]
    host = host.split("/", 1)[0]

    host = host.strip().lower()

    if host.startswith("www."):
        host = host[4:]

    return host
