"""
WHOIS routes.

Exposes the /whois endpoint, which accepts a domain via POST and
delegates all lookup logic to modules/whois_lookup.py. This route
contains no WHOIS logic itself.
"""

from flask import Blueprint, request, jsonify

from modules.whois_lookup import lookup_domain
from app.utils.validators import normalize_domain

whois_bp = Blueprint("whois", __name__)


@whois_bp.route("/whois", methods=["POST"])
def whois_lookup_route():
    """Receive a domain, run a WHOIS lookup, and return the results."""
    domain = normalize_domain(request.form.get("domain", ""))

    if not domain:
        return jsonify({
            "status": "error",
            "message": "Domain is required."
        }), 400

    print(f"[WHOIS] Looking up domain: {domain}")

    result = lookup_domain(domain)

    if "error" in result:
        print(f"[WHOIS] Error: {result['error']}")
        return jsonify({
            "status": "error",
            "message": result["error"]
        })

    return jsonify({
        "status": "success",
        "domain": domain,
        "data": result
    })
