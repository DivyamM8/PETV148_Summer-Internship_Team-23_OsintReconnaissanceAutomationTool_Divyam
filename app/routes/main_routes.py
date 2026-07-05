"""
Main routes: homepage, subdomain discovery, SSL certificate lookup,
email harvesting, social footprint link generation, and the
integrated full report.

The homepage renders the domain input form. WHOIS, DNS, and Shodan
each have their own dedicated route files (whois_routes.py,
dns_routes.py, shodan_routes.py); subdomain discovery, SSL lookup,
email harvesting, social footprint generation, and the final
integrated report are kept here since no dedicated route files were
created for them.
"""

import json

from flask import Blueprint, render_template, request, jsonify, Response

from modules.subdomain import discover_subdomains
from modules.ssl_lookup import get_certificate_info
from modules.email_lookup import harvest_emails
from modules.social import generate_social_links
from modules.report_generator import generate_report
from modules.report_formatter import build_html_report, build_pdf_report
from app.utils.validators import normalize_domain

main_bp = Blueprint("main", __name__)


@main_bp.route("/", methods=["GET"])
def index():
    """Render the homepage."""
    return render_template("index.html")


@main_bp.route("/subdomains", methods=["POST"])
def subdomains_route():
    """Receive a domain, passively discover subdomains, and return them."""
    domain = normalize_domain(request.form.get("domain", ""))

    if not domain:
        return jsonify({
            "status": "error",
            "message": "Domain is required."
        }), 400

    print(f"[Subdomains] Discovering subdomains for domain: {domain}")

    result = discover_subdomains(domain)

    if "error" in result:
        print(f"[Subdomains] Error: {result['error']}")
        return jsonify({
            "status": "error",
            "message": result["error"]
        })

    return jsonify({
        "status": "success",
        "domain": domain,
        "data": result
    })


@main_bp.route("/ssl", methods=["POST"])
def ssl_route():
    """Receive a domain, look up its SSL certificate info, and return it."""
    domain = normalize_domain(request.form.get("domain", ""))

    if not domain:
        return jsonify({
            "status": "error",
            "message": "Domain is required."
        }), 400

    print(f"[SSL] Looking up certificate info for domain: {domain}")

    result = get_certificate_info(domain)

    if "error" in result:
        print(f"[SSL] Error: {result['error']}")
        return jsonify({
            "status": "error",
            "message": result["error"]
        })

    return jsonify({
        "status": "success",
        "domain": domain,
        "data": result
    })


@main_bp.route("/email", methods=["POST"])
def email_route():
    """Receive a domain, passively harvest emails, and return them."""
    domain = normalize_domain(request.form.get("domain", ""))

    if not domain:
        return jsonify({
            "status": "error",
            "message": "Domain is required."
        }), 400

    print(f"[Email] Harvesting emails for domain: {domain}")

    result = harvest_emails(domain)

    if "error" in result:
        print(f"[Email] Error: {result['error']}")
        return jsonify({
            "status": "error",
            "message": result["error"]
        })

    return jsonify({
        "status": "success",
        "domain": domain,
        "data": result
    })


@main_bp.route("/social", methods=["POST"])
def social_route():
    """Receive a domain, generate social footprint search URLs, and return them."""
    domain = normalize_domain(request.form.get("domain", ""))

    if not domain:
        return jsonify({
            "status": "error",
            "message": "Domain is required."
        }), 400

    print(f"[Social] Generating social search links for domain: {domain}")

    result = generate_social_links(domain)

    if "error" in result:
        print(f"[Social] Error: {result['error']}")
        return jsonify({
            "status": "error",
            "message": result["error"]
        })

    return jsonify({
        "status": "success",
        "domain": domain,
        "data": result
    })


@main_bp.route("/report", methods=["GET"])
def report_route():
    """
    Render the integrated report page.

    If a domain is supplied via ?domain=..., runs every reconnaissance
    module (through modules/report_generator.py) and displays all
    sections (WHOIS, DNS, Subdomains, Emails, SSL, Shodan, Social) on
    one page. With no domain supplied, shows just the input form.
    """
    domain = normalize_domain(request.args.get("domain", ""))

    report = None
    if domain:
        print(f"[Report] Generating full report for domain: {domain}")
        report = generate_report(domain)

    return render_template("report.html", domain=domain, report=report)


@main_bp.route("/report/download", methods=["GET"])
def report_download_route():
    """Generate the full report for a domain and return it as a downloadable JSON file."""
    domain = normalize_domain(request.args.get("domain", ""))

    if not domain:
        return jsonify({
            "status": "error",
            "message": "Domain is required."
        }), 400

    print(f"[Report] Generating downloadable JSON report for domain: {domain}")

    report = generate_report(domain)
    json_data = json.dumps(report, indent=2, default=str)

    return Response(
        json_data,
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={domain}_report.json"
        }
    )


@main_bp.route("/report/download/html", methods=["GET"])
def report_download_html_route():
    """Generate the full report for a domain and return it as a downloadable HTML file."""
    domain = normalize_domain(request.args.get("domain", ""))

    if not domain:
        return jsonify({
            "status": "error",
            "message": "Domain is required."
        }), 400

    print(f"[Report] Generating downloadable HTML report for domain: {domain}")

    report = generate_report(domain)
    html_document = build_html_report(report)

    return Response(
        html_document,
        mimetype="text/html",
        headers={
            "Content-Disposition": f"attachment; filename={domain}_report.html"
        }
    )


@main_bp.route("/report/download/pdf", methods=["GET"])
def report_download_pdf_route():
    """Generate the full report for a domain and return it as a downloadable PDF file."""
    domain = normalize_domain(request.args.get("domain", ""))

    if not domain:
        return jsonify({
            "status": "error",
            "message": "Domain is required."
        }), 400

    print(f"[Report] Generating downloadable PDF report for domain: {domain}")

    report = generate_report(domain)
    pdf_bytes = build_pdf_report(report)

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={domain}_report.pdf"
        }
    )


@main_bp.route("/report/export/html", methods=["POST"])
def report_export_html_route():
    """
    Build a downloadable HTML report from data the browser already
    collected during the live scan (sent as JSON in the request body).

    Unlike /report/download/html, this performs NO fresh reconnaissance
    lookups — it only formats the data it's given — so it returns
    almost instantly instead of re-running every module from scratch.
    """
    payload = request.get_json(silent=True)

    if not payload or not payload.get("domain"):
        return jsonify({
            "status": "error",
            "message": "Domain and scan data are required."
        }), 400

    domain = payload["domain"]
    print(f"[Report] Exporting HTML report from already-collected data for domain: {domain}")

    html_document = build_html_report(payload)

    return Response(
        html_document,
        mimetype="text/html",
        headers={
            "Content-Disposition": f"attachment; filename={domain}_report.html"
        }
    )


@main_bp.route("/report/export/pdf", methods=["POST"])
def report_export_pdf_route():
    """
    Build a downloadable PDF report from data the browser already
    collected during the live scan (sent as JSON in the request body).

    Unlike /report/download/pdf, this performs NO fresh reconnaissance
    lookups — it only formats the data it's given — so it returns
    almost instantly instead of re-running every module from scratch.
    """
    payload = request.get_json(silent=True)

    if not payload or not payload.get("domain"):
        return jsonify({
            "status": "error",
            "message": "Domain and scan data are required."
        }), 400

    domain = payload["domain"]
    print(f"[Report] Exporting PDF report from already-collected data for domain: {domain}")

    pdf_bytes = build_pdf_report(payload)

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={domain}_report.pdf"
        }
    )
