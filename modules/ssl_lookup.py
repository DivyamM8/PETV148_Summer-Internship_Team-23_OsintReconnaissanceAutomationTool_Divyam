"""
SSL certificate lookup module.

Contains ALL SSL certificate lookup logic for the OSINT
Reconnaissance Automation Tool.

Primary source: a live TLS handshake with the target host (with SNI,
via `ssl`/`socket`), which is what a browser does and reflects the
certificate the server is actually presenting right now. This fixes
false "SSL unavailable" results for domains (e.g. google.com,
python.org) whose current certificate simply hasn't been indexed by
a particular Certificate Transparency log mirror.

Fallback source: crt.sh (Certificate Transparency log search), used
only when the live handshake itself cannot be completed (e.g. the
host blocks the connection, or blocks port 443 for automated
clients).

Flask routes must call `get_certificate_info()` from this module.
Failures are classified into the real, specific reason (SSL
handshake failed, connection timed out, host unreachable, no
certificate found) instead of one generic message. Any technical
failure detail is logged to the terminal only; callers receive a
short, user-friendly message instead of a raw exception.
"""

import socket
import ssl
import time
from datetime import datetime

import requests

CRTSH_URL = "https://crt.sh/"
REQUEST_TIMEOUT = 25
REQUEST_HEADERS = {"User-Agent": "OSINT-Recon-Tool/1.0"}
NOT_FOUND = "Not Found"

MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2

# crt.sh timestamps look like "2026-01-01T00:00:00"
CRTSH_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

TLS_PORT = 443
TLS_CONNECT_TIMEOUT = 10

# Live-handshake certificate timestamps look like "Jun  1 12:00:00 2026 GMT"
TLS_CERT_DATETIME_FORMAT = "%b %d %H:%M:%S %Y %Z"

ERROR_HANDSHAKE_FAILED = "SSL handshake failed."
ERROR_TIMED_OUT = "Connection timed out."
ERROR_UNREACHABLE = "Host unreachable."
ERROR_NO_CERTIFICATE = "No certificate found."


def _log(message):
    """Log technical details to the terminal only (never shown to the user)."""
    print(f"[SSL Module] {message}")


def _format_cert_datetime(raw_value):
    """
    Reformat a certificate timestamp into a consistent, readable
    string. Falls back to the raw value if it can't be parsed.
    """
    if not raw_value:
        return NOT_FOUND
    try:
        parsed = datetime.strptime(raw_value, TLS_CERT_DATETIME_FORMAT)
        return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return raw_value


def _extract_rdn_field(rdn_sequence, field_name):
    """
    Extract a named field (e.g. "commonName", "organizationName")
    from the tuple-of-tuples structure `ssl`'s getpeercert() uses for
    "subject" and "issuer".
    """
    if not rdn_sequence:
        return None
    for rdn in rdn_sequence:
        for key, value in rdn:
            if key == field_name:
                return value
    return None


def _extract_common_name(cert):
    """
    Determine the best "common name" to display: the certificate
    subject's commonName, falling back to the first DNS entry in the
    Subject Alternative Name extension if commonName is absent (some
    modern certificates, notably from public CAs, omit it).
    """
    common_name = _extract_rdn_field(cert.get("subject"), "commonName")
    if common_name:
        return common_name

    for entry_type, entry_value in cert.get("subjectAltName", ()):
        if entry_type == "DNS":
            return entry_value

    return None


def _extract_issuer(cert):
    """Build a readable issuer string from the certificate's issuer RDNs."""
    issuer_rdns = cert.get("issuer")
    organization = _extract_rdn_field(issuer_rdns, "organizationName")
    common_name = _extract_rdn_field(issuer_rdns, "commonName")

    parts = [part for part in (common_name, organization) if part]
    return ", ".join(parts) if parts else None


def _fetch_live_certificate(domain):
    """
    Perform a live TLS handshake with `domain` on port 443, using SNI
    so name-based virtual hosting (shared IPs, CDNs) returns the
    correct certificate, and return its parsed details.

    Returns:
        tuple(dict | None, str | None):
            - Parsed certificate dict on success, with error=None, or
            - (None, error_message) using one of the four
              user-friendly error constants above.
    """
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, TLS_PORT), timeout=TLS_CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
    except socket.timeout:
        _log(f"Live TLS connection to '{domain}' timed out.")
        return None, ERROR_TIMED_OUT
    except (socket.gaierror, ConnectionRefusedError, OSError) as exc:
        _log(f"Live TLS connection to '{domain}' failed (host unreachable): {exc!r}")
        return None, ERROR_UNREACHABLE
    except ssl.SSLError as exc:
        _log(f"Live TLS handshake with '{domain}' failed: {exc!r}")
        return None, ERROR_HANDSHAKE_FAILED
    except Exception as exc:
        _log(f"Unexpected error during live TLS handshake with '{domain}': {exc!r}")
        return None, ERROR_HANDSHAKE_FAILED

    if not cert:
        _log(f"Live TLS handshake with '{domain}' succeeded but returned no certificate.")
        return None, ERROR_NO_CERTIFICATE

    return cert, None


def _get_live_certificate_info(domain):
    """
    Retrieve certificate details via a live TLS handshake and shape
    them into this module's standard success/error result dict.
    """
    cert, error_message = _fetch_live_certificate(domain)
    if cert is None:
        return {"error": error_message}

    _log(f"Live TLS certificate retrieved for '{domain}'.")

    return {
        "common_name": _extract_common_name(cert) or NOT_FOUND,
        "issuer": _extract_issuer(cert) or NOT_FOUND,
        "valid_from": _format_cert_datetime(cert.get("notBefore")),
        "valid_until": _format_cert_datetime(cert.get("notAfter")),
    }


def _classify_request_exception(exc):
    """
    Turn the exception from the final failed crt.sh request attempt
    into a short, specific, user-friendly message. The raw exception
    is logged separately by the caller; this function never returns
    raw exception text.
    """
    if isinstance(exc, requests.exceptions.Timeout):
        return ERROR_TIMED_OUT

    if isinstance(exc, requests.exceptions.ConnectionError):
        return ERROR_UNREACHABLE

    if isinstance(exc, requests.exceptions.HTTPError):
        return "Certificate Transparency unavailable."

    if isinstance(exc, ValueError):
        return "Certificate lookup failed: invalid response received."

    if isinstance(exc, requests.exceptions.RequestException):
        return "SSL retrieval error."

    return "Certificate service unavailable."


def _fetch_crtsh_entries(domain):
    """
    Query crt.sh for a domain's certificate history, retrying up to
    MAX_RETRIES times with a short delay between attempts. Used only
    as a fallback when the live TLS handshake cannot be completed.

    Returns:
        tuple(list | None, str | None):
            - Parsed JSON entries on success (possibly an empty list
              if the domain has no certificates), with error=None, or
            - (None, error_message) if every attempt failed.
    """
    params = {"q": domain, "output": "json"}
    last_exception = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                CRTSH_URL, params=params, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS
            )
            response.raise_for_status()
            return response.json(), None
        except (requests.exceptions.RequestException, ValueError) as exc:
            last_exception = exc
            _log(f"crt.sh attempt {attempt}/{MAX_RETRIES} failed for '{domain}': {exc!r}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY_SECONDS)

    _log(f"crt.sh unavailable for '{domain}' after {MAX_RETRIES} attempts. Final error: {last_exception!r}")
    return None, _classify_request_exception(last_exception)


def _parse_datetime(value):
    """Parse a crt.sh timestamp string, returning None if invalid/missing."""
    if not value:
        return None
    try:
        return datetime.strptime(value, CRTSH_DATETIME_FORMAT)
    except (ValueError, TypeError):
        return None


def _select_newest_certificate(entries):
    """
    Choose the best certificate entry to display from crt.sh fallback
    results.

    Prefers the newest certificate that is currently valid (its
    validity window contains "now"). If none are currently valid,
    falls back to the single most recently issued certificate.
    """
    now = datetime.utcnow()

    currently_valid = []
    for entry in entries:
        not_before = _parse_datetime(entry.get("not_before"))
        not_after = _parse_datetime(entry.get("not_after"))
        if not_before and not_after and not_before <= now <= not_after:
            currently_valid.append((not_before, entry))

    if currently_valid:
        currently_valid.sort(key=lambda pair: pair[0], reverse=True)
        return currently_valid[0][1]

    # Fall back to the most recently issued certificate overall.
    dated_entries = [
        (_parse_datetime(entry.get("not_before")) or datetime.min, entry)
        for entry in entries
    ]
    dated_entries.sort(key=lambda pair: pair[0], reverse=True)
    return dated_entries[0][1]


def _get_crtsh_fallback_info(domain):
    """
    Retrieve certificate details from crt.sh Certificate Transparency
    logs. Only called when the live TLS handshake fails.
    """
    entries, error_message = _fetch_crtsh_entries(domain)

    if entries is None:
        return {"error": error_message}

    # A domain with no certificate history via either method is not a
    # crt.sh-specific failure, just an empty (but valid) result.
    if not entries:
        return {"error": ERROR_NO_CERTIFICATE}

    try:
        newest = _select_newest_certificate(entries)
    except Exception as exc:
        _log(f"Failed to select newest certificate for '{domain}': {exc!r}")
        return {"error": "Certificate lookup failed: invalid response received."}

    return {
        "common_name": newest.get("common_name") or NOT_FOUND,
        "issuer": newest.get("issuer_name") or NOT_FOUND,
        "valid_from": newest.get("not_before") or NOT_FOUND,
        "valid_until": newest.get("not_after") or NOT_FOUND,
    }


def get_certificate_info(domain):
    """
    Retrieve certificate details for a domain.

    Primary source is a live TLS handshake (with SNI) against the
    domain on port 443 — the same thing a browser does — so the
    result reflects the certificate the server is presenting right
    now. Certificate Transparency (crt.sh) is used only as a fallback
    if the live handshake itself cannot be completed.

    Args:
        domain (str): The domain to look up (e.g. "example.com").

    Returns:
        dict: On success:
            {
                "common_name": str,
                "issuer": str,
                "valid_from": str,
                "valid_until": str
            }
            On failure:
            {
                "error": str   # one of: "SSL handshake failed.",
                                # "Connection timed out.",
                                # "Host unreachable.",
                                # "No certificate found."
            }
    """
    if not domain:
        return {"error": "No domain provided."}

    live_result = _get_live_certificate_info(domain)
    if "error" not in live_result:
        return live_result

    _log(f"Live TLS retrieval failed for '{domain}' ({live_result['error']}); falling back to crt.sh.")

    fallback_result = _get_crtsh_fallback_info(domain)
    if "error" not in fallback_result:
        return fallback_result

    # Both sources failed: prefer the live handshake's more specific
    # error, since it reflects what actually happened when reaching
    # the host itself rather than a third-party CT log.
    return live_result
