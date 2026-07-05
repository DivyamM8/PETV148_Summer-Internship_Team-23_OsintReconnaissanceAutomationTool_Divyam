"""
Shodan lookup module.

Contains ALL Shodan logic for the OSINT Reconnaissance Automation
Tool, using the official `shodan` Python library. The API key is
read from the SHODAN_API_KEY environment variable (loaded from a
local .env file via python-dotenv in config/config.py).

Flask routes must call `lookup_host()` from this module. Every
failure path is classified individually (invalid API key, query
limit exceeded, no data available, DNS resolution failure, invalid
IP, network timeout, connection error, or an unexpected API
response) so the UI shows the real reason instead of one generic
message. Full technical detail (resolved IP, IP sent to Shodan, the
raw Shodan response, and exception tracebacks) is always logged to
the terminal only, never returned to the caller/webpage.
"""

import ipaddress
import os
import socket
import traceback

import requests
import shodan
from dotenv import load_dotenv

# Ensures SHODAN_API_KEY is available even if this module is used
# independently of the Flask app factory.
load_dotenv()

NOT_FOUND = "Not Found"
REQUEST_TIMEOUT = 15


def _log(message):
    """Log technical details to the terminal only (never shown to the user)."""
    print(f"[Shodan Module] {message}")


def _get_api_key():
    """Read the Shodan API key from the environment."""
    return os.environ.get("SHODAN_API_KEY")


def _classify_network_context(exc):
    """
    shodan.Shodan.host() wraps ANY exception raised while contacting
    the API (timeouts, connection errors, DNS failures inside
    `requests`, etc.) into a single generic
    shodan.exception.APIError('Unable to connect to Shodan'),
    discarding the specific reason from its own message text.

    However, Python automatically preserves the original exception on
    `exc.__context__` even without an explicit `raise ... from`, so we
    can inspect it here to recover the real, specific cause.
    """
    context = exc.__context__
    if context is None:
        return "Connection error while contacting Shodan."

    if isinstance(context, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout,
                             requests.exceptions.Timeout, socket.timeout)):
        return "Network timeout while contacting Shodan."

    if isinstance(context, requests.exceptions.ConnectionError):
        return "Connection error while contacting Shodan."

    return "Connection error while contacting Shodan."


def _classify_api_error(exc):
    """
    Turn a shodan.exception.APIError into a short, specific,
    user-friendly message by inspecting its text and (for the
    library's generic connection-failure message) its wrapped
    __context__ exception. The raw exception and its traceback are
    logged separately by the caller; this function never returns raw
    exception text.
    """
    message = str(exc).lower()

    if "invalid api key" in message:
        return "Invalid API key."

    if any(phrase in message for phrase in ("query limit", "usage limit", "rate limit", "plan limit")):
        return "Query limit exceeded."

    if any(phrase in message for phrase in ("no information available", "not found")):
        return "No Shodan data available for this IP."

    if "invalid ip" in message:
        return "Invalid IP."

    if "access denied" in message or "403" in message:
        return "Access denied: insufficient permissions for this Shodan API key."

    if "unable to connect to shodan" in message:
        return _classify_network_context(exc)

    if "unable to parse json" in message or "bad gateway" in message:
        return "Unexpected API response from Shodan."

    return "Unexpected API response from Shodan."


def lookup_host(domain):
    """
    Resolve a domain to an IP address and retrieve its Shodan host
    information.

    Args:
        domain (str): The domain to look up (e.g. "example.com").

    Returns:
        dict: On success:
            {
                "ip": str,
                "isp": str,
                "organization": str,
                "open_ports": list[int],   # "Not Found" if none
                "operating_system": str
            }
            On failure:
            {
                "error": str   # short, specific, user-friendly message
            }
    """
    if not domain:
        return {"error": "No domain provided."}

    api_key = _get_api_key()
    if not api_key:
        _log(f"Lookup requested for '{domain}' but SHODAN_API_KEY is not set.")
        return {"error": "Shodan API key not configured. Set SHODAN_API_KEY in .env."}

    try:
        # getaddrinfo (vs. the legacy gethostbyname) correctly handles
        # IPv6-only hosts, CDN/Anycast setups, and modern DNS records
        # in general. AF_UNSPEC lets the resolver return whichever
        # family the domain actually has; IPv4 is preferred when both
        # are available since Shodan's API is keyed on IPv4 hosts.
        addr_info = socket.getaddrinfo(domain, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        _log(f"DNS resolution failed for '{domain}': {exc}")
        return {"error": "DNS resolution failed."}

    ipv4_addresses = [info[4][0] for info in addr_info if info[0] == socket.AF_INET]
    ipv6_addresses = [info[4][0] for info in addr_info if info[0] == socket.AF_INET6]
    ip_address = (ipv4_addresses or ipv6_addresses or [None])[0]

    if not ip_address:
        _log(f"getaddrinfo returned no usable address for '{domain}'.")
        return {"error": "DNS resolution failed."}

    _log(f"Resolved IP address for '{domain}': {ip_address}")

    # Defensive check: confirm the resolved value is actually a valid
    # IP address before handing it to the Shodan API.
    try:
        ipaddress.ip_address(ip_address)
    except ValueError as exc:
        _log(f"Resolved value is not a valid IP for '{domain}': {ip_address} ({exc})")
        return {"error": "Invalid IP."}

    _log(f"Sending IP to Shodan for '{domain}': {ip_address}")

    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip_address)
    except shodan.exception.APIError as exc:
        _log(f"Shodan APIError for '{domain}' ({ip_address}): {exc!r} (context: {exc.__context__!r})")
        _log(f"Traceback:\n{traceback.format_exc()}")
        return {"error": _classify_api_error(exc)}
    except Exception as exc:
        _log(f"Unexpected exception during Shodan lookup for '{domain}' ({ip_address}): {exc!r}")
        _log(f"Traceback:\n{traceback.format_exc()}")
        return {"error": "Unexpected API response from Shodan."}

    _log(f"Raw Shodan response for '{domain}' ({ip_address}): {host}")

    ports = sorted(host.get("ports", []))

    return {
        "ip": ip_address,
        "isp": host.get("isp") or NOT_FOUND,
        "organization": host.get("org") or NOT_FOUND,
        "open_ports": ports if ports else NOT_FOUND,
        "operating_system": host.get("os") or NOT_FOUND,
    }
