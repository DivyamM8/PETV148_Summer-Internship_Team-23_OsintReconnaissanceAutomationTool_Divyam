"""
Social footprint module.

Contains ALL social footprint logic for the OSINT Reconnaissance
Automation Tool. This module does not query any social platform's
API; it only generates safe, pre-built search URLs (LinkedIn, GitHub,
Twitter, Facebook) that a user can open manually to review a
target's public social footprint.

Flask routes must call `generate_social_links()` from this module.
"""

from urllib.parse import quote_plus

NOT_FOUND = "Not Found"


def generate_social_links(domain):
    """
    Generate search URLs for common social/professional platforms
    based on a domain name.

    Args:
        domain (str): The domain to search for (e.g. "example.com").

    Returns:
        dict: On success:
            {
                "linkedin": str,
                "github": str,
                "twitter": str,
                "facebook": str
            }
            On failure:
            {
                "error": str
            }
    """
    if not domain:
        return {"error": "No domain provided."}

    query = quote_plus(domain)

    links = {
        "linkedin": f"https://www.linkedin.com/search/results/companies/?keywords={query}",
        "github": f"https://github.com/search?q={query}&type=repositories",
        "twitter": f"https://twitter.com/search?q={query}",
        "facebook": f"https://www.facebook.com/search/top/?q={query}",
    }

    # Handled gracefully: URL generation cannot fail once a domain
    # is provided, but each field still falls back to "Not Found"
    # defensively in case of an unexpected empty value.
    return {key: (value or NOT_FOUND) for key, value in links.items()}
