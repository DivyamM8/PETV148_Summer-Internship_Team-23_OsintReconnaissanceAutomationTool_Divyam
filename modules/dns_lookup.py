"""
DNS enumeration module.

Contains ALL DNS lookup logic for the OSINT Reconnaissance Automation
Tool. Flask routes must call `lookup_dns_records()` from this module
rather than querying dnspython directly.

Record types retrieved:
    A, AAAA, MX, TXT, NS, CNAME, SOA

Each record type is looked up independently so that one missing or
failing record type does not prevent the others from being returned.
A record type with no results is reported as "Not Found".
"""

import dns.resolver
import dns.exception


NOT_FOUND = "Not Found"

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


def _format_record(rdata, record_type):
    """
    Convert a single dnspython rdata object into a readable string.

    Some record types (MX, SOA) have multiple fields, so they are
    formatted specially for clarity; the rest are converted directly
    to their string representation.
    """
    if record_type == "MX":
        return f"{rdata.preference} {rdata.exchange}"
    if record_type == "SOA":
        return (
            f"mname={rdata.mname} rname={rdata.rname} "
            f"serial={rdata.serial} refresh={rdata.refresh} "
            f"retry={rdata.retry} expire={rdata.expire} "
            f"minimum={rdata.minimum}"
        )
    return str(rdata).strip()


def _lookup_single_record(domain, record_type):
    """
    Query a single DNS record type for a domain.

    Returns:
        list[str]: A list of formatted record values, or an empty
        list if the record does not exist or the query fails.
    """
    try:
        answer = dns.resolver.resolve(domain, record_type)
        return [_format_record(rdata, record_type) for rdata in answer]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoNameservers:
        return []
    except dns.exception.Timeout:
        return []
    except Exception:
        return []


def lookup_dns_records(domain):
    """
    Retrieve A, AAAA, MX, TXT, NS, CNAME, and SOA records for a domain.

    Args:
        domain (str): The domain name to query (e.g. "example.com").

    Returns:
        dict: On success, one key per record type mapped to either a
            list of record strings or "Not Found" if none exist:
            {
                "A": [...],
                "AAAA": [...],
                "MX": [...],
                "TXT": [...],
                "NS": [...],
                "CNAME": [...],
                "SOA": [...]
            }
            On failure (e.g. invalid/non-existent domain entirely):
            {
                "error": str
            }
    """
    if not domain:
        return {"error": "No domain provided."}

    # First confirm the domain resolves at all (NXDOMAIN check via A).
    # If every record type comes back empty, we still return the
    # per-type "Not Found" results rather than a hard error, since a
    # domain can legitimately lack some record types (e.g. no MX).
    results = {}

    try:
        for record_type in RECORD_TYPES:
            records = _lookup_single_record(domain, record_type)
            results[record_type] = records if records else NOT_FOUND
    except Exception as exc:
        return {"error": f"DNS enumeration failed for '{domain}': {exc}"}

    return results
