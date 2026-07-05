"""
Report generator module.

Integrates every existing reconnaissance module into a single report.
This module contains NO lookup logic of its own — it only imports
and calls the existing, unmodified modules and combines their
results into one dictionary suitable for rendering a report page or
exporting as JSON.
"""

from modules.whois_lookup import lookup_domain
from modules.dns_lookup import lookup_dns_records
from modules.subdomain import discover_subdomains
from modules.ssl_lookup import get_certificate_info
from modules.shodan_lookup import lookup_host
from modules.email_lookup import harvest_emails
from modules.social import generate_social_links


def generate_report(domain):
    """
    Run every reconnaissance module for a domain and combine the
    results into a single report dictionary.

    A failure in any one section (returned as that module's normal
    {"error": ...} shape) does not prevent the other sections from
    running, since each module is called independently.

    Args:
        domain (str): The domain to investigate (e.g. "example.com").

    Returns:
        dict: {
            "domain": str,
            "whois": {...},
            "dns": {...},
            "subdomains": {...},
            "ssl": {...},
            "shodan": {...},
            "email": {...},
            "social": {...}
        }
    """
    return {
        "domain": domain,
        "whois": lookup_domain(domain),
        "dns": lookup_dns_records(domain),
        "subdomains": discover_subdomains(domain),
        "ssl": get_certificate_info(domain),
        "shodan": lookup_host(domain),
        "email": harvest_emails(domain),
        "social": generate_social_links(domain),
    }
