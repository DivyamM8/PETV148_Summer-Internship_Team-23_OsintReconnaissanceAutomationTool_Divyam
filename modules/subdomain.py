"""
Passive subdomain discovery module.

Contains ALL subdomain discovery logic for the OSINT Reconnaissance
Automation Tool. Discovery is done passively using only the
`requests` library — no direct scanning or contact with the target's
infrastructure.

Primary source: crt.sh (Certificate Transparency log search).
crt.sh is a free, community-run service that occasionally returns
502 errors or times out under load. On cloud deployments (e.g. Render
running under Gunicorn), the worker process is killed after ~30
seconds, so this module is tuned to fail fast on crt.sh and move on
to the fallback sources — HackerTarget and BufferOver — rather than
burning the whole request budget on retries against a single source.

Flask routes must call `discover_subdomains()` from this module.
Any technical failure detail is logged to the terminal only; callers
receive a short, user-friendly message instead of a raw exception.
"""

import time
import requests

CRTSH_URL = "https://crt.sh/"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/"
BUFFEROVER_URL = "https://dns.bufferover.run/dns"

# Kept short and cloud-friendly. On Render, Gunicorn kills the worker
# after ~30s, and crt.sh's 502s/timeouts alone could previously eat
# the whole budget before fallbacks were ever tried.
REQUEST_TIMEOUT = 6
REQUEST_HEADERS = {"User-Agent": "OSINT-Recon-Tool/1.0"}

# crt.sh is retried only once (i.e. no retry, single attempt) so that
# we fail fast and still have time left over for the fallback sources.
MAX_RETRIES = 1
RETRY_DELAY_SECONDS = 2


def _log(message):
    """Log technical details to the terminal only (never shown to the user)."""
    print(f"[Subdomain Module] {message}")


def _fetch_crtsh(domain):
    """
    Query crt.sh for a domain. Retries up to MAX_RETRIES times (fail
    fast by default — MAX_RETRIES = 1 — so the fallback sources still
    have time to run within the platform's request/worker timeout).

    Returns:
        list | None: Parsed JSON entries on success, or None if every
        attempt failed (network error, bad status, or invalid JSON).
    """
    params = {"q": f"%.{domain}", "output": "json"}

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                CRTSH_URL, params=params, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS
            )
            response.raise_for_status()
            return response.json()
        except (requests.exceptions.RequestException, ValueError) as exc:
            _log(f"crt.sh attempt {attempt}/{MAX_RETRIES} failed for '{domain}': {exc}")
            # Only sleep if another attempt is actually going to happen.
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY_SECONDS)

    _log(f"crt.sh unavailable for '{domain}' after {MAX_RETRIES} attempt(s).")
    return None


def _fetch_hackertarget(domain):
    """
    Fallback passive source #1: HackerTarget's hostsearch API.

    Returns:
        set[str] | None: A set of subdomains (possibly empty) on
        success, or None if the request failed entirely.
    """
    try:
        response = requests.get(
            HACKERTARGET_URL, params={"q": domain}, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        _log(f"HackerTarget fallback failed for '{domain}': {exc}")
        return None

    text = response.text.strip()

    # HackerTarget returns a plain-text error message (e.g. rate limit
    # notice) instead of host data when it can't fulfil the request.
    if not text or "error" in text.lower() or "api count exceeded" in text.lower():
        _log(f"HackerTarget returned no usable data for '{domain}': {text[:120]!r}")
        return set()

    subdomains = set()
    for line in text.splitlines():
        host = line.split(",")[0].strip().lower()
        if host and host.endswith(domain.lower()):
            subdomains.add(host)

    return subdomains


def _fetch_bufferover(domain):
    """
    Fallback passive source #2: BufferOver's DNS/Certificate dataset.

    Returns:
        set[str] | None: A set of subdomains (possibly empty) on
        success, or None if the request failed entirely.
    """
    try:
        response = requests.get(
            BUFFEROVER_URL, params={"q": f".{domain}"}, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS
        )
        response.raise_for_status()
        data = response.json()
    except (requests.exceptions.RequestException, ValueError) as exc:
        _log(f"BufferOver fallback failed for '{domain}': {exc}")
        return None

    subdomains = set()
    for key in ("FDNS_A", "RDNS"):
        for entry in (data.get(key) or []):
            # Entries are formatted like "1.2.3.4,host.example.com"
            parts = entry.split(",")
            host = parts[-1].strip().lower()
            if host and host.endswith(domain.lower()):
                subdomains.add(host)

    return subdomains


def discover_subdomains(domain):
    """
    Passively discover subdomains for a domain, trying crt.sh first
    (fail-fast, single attempt) and, if that's unavailable, querying
    both HackerTarget and BufferOver and merging whatever results
    they return. This avoids returning an artificially small result
    just because one of the two fallback sources happened to fail.

    Args:
        domain (str): The root domain to search (e.g. "example.com").

    Returns:
        dict: On success:
            {
                "subdomains": list[str]   # empty list if none found
            }
            On failure (all sources unavailable):
            {
                "error": str   # short, user-friendly message
            }
    """
    if not domain:
        return {"error": "No domain provided."}

    entries = _fetch_crtsh(domain)
    if entries is not None:
        subdomains = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and name.endswith(domain.lower()):
                    subdomains.add(name)
        # Handled gracefully: an empty list is a valid, non-error result.
        return {"subdomains": sorted(subdomains)}

    # crt.sh failed — immediately move on to the fallback sources
    # rather than spending more time retrying it. Both fallbacks are
    # queried and, if they succeed, their results are merged so a
    # single failing provider doesn't shrink the final result set.
    _log(f"Falling back to HackerTarget for '{domain}'.")
    hackertarget_result = _fetch_hackertarget(domain)

    _log(f"Falling back to BufferOver for '{domain}'.")
    bufferover_result = _fetch_bufferover(domain)

    if hackertarget_result is None and bufferover_result is None:
        _log(f"All subdomain discovery sources failed for '{domain}'.")
        return {"error": "Subdomain discovery is currently unavailable. Please try again later."}

    merged = set()
    if hackertarget_result:
        merged |= hackertarget_result
    if bufferover_result:
        merged |= bufferover_result

    return {"subdomains": sorted(merged)}