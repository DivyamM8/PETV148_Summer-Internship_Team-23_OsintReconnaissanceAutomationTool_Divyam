"""
Shodan routes.

Exposes the /shodan endpoint, which accepts a domain via POST and
delegates all lookup logic to modules/shodan_lookup.py. This route
contains no Shodan logic itself.
"""

from flask import Blueprint, request, jsonify

from modules.shodan_lookup import lookup_host
from app.utils.validators import normalize_domain

shodan_bp = Blueprint("shodan", __name__)


@shodan_bp.route("/shodan", methods=["POST"])
def shodan_lookup_route():
    """Receive a domain, run a Shodan host lookup, and return the results."""
    domain = normalize_domain(request.form.get("domain", ""))

    if not domain:
        return jsonify({
            "status": "error",
            "message": "Domain is required."
        }), 400

    print(f"[Shodan] Looking up host info for domain: {domain}")

    result = lookup_host(domain)

    if "error" in result:
        print(f"[Shodan] Error: {result['error']}")
        return jsonify({
            "status": "error",
            "message": result["error"]
        })

    return jsonify({
        "status": "success",
        "domain": domain,
        "data": result
    })
