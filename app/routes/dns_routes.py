"""
DNS routes.

Exposes the /dns endpoint, which accepts a domain via POST and
delegates all lookup logic to modules/dns_lookup.py. This route
contains no DNS logic itself.
"""

from flask import Blueprint, request, jsonify

from modules.dns_lookup import lookup_dns_records
from app.utils.validators import normalize_domain

dns_bp = Blueprint("dns", __name__)


@dns_bp.route("/dns", methods=["POST"])
def dns_lookup_route():
    """Receive a domain, run DNS enumeration, and return the results."""
    domain = normalize_domain(request.form.get("domain", ""))

    if not domain:
        return jsonify({
            "status": "error",
            "message": "Domain is required."
        }), 400

    print(f"[DNS] Enumerating records for domain: {domain}")

    result = lookup_dns_records(domain)

    if "error" in result:
        print(f"[DNS] Error: {result['error']}")
        return jsonify({
            "status": "error",
            "message": result["error"]
        })

    return jsonify({
        "status": "success",
        "domain": domain,
        "data": result
    })
