"""
Report formatting module (presentation layer only).

This module contains NO reconnaissance logic. It only formats the
dictionary produced by modules/report_generator.py (or an equivalent
dict reconstructed on the server from data the browser already
collected during the live scan) into two downloadable file formats:

    - build_html_report(report)  -> standalone HTML string
    - build_pdf_report(report)   -> PDF file bytes (via fpdf2)

Used by app/routes/main_routes.py to power the "Download HTML
Report" and "Download PDF Report" buttons on the homepage.
"""

from datetime import datetime

from fpdf import FPDF

NOT_FOUND = "Not Found"
CRTSH_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

SOCIAL_BUTTON_LABELS = (
    ("LinkedIn", "linkedin"),
    ("GitHub", "github"),
    ("Twitter", "twitter"),
    ("Facebook", "facebook"),
)


def _display(value):
    """Format a value (list, string, or missing) for display."""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value) if value else NOT_FOUND
    if value in (None, ""):
        return NOT_FOUND
    return str(value)


def _escape_html(text):
    """Minimal HTML-escaping for safe embedding of scanned data."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------
# Executive Summary (shared by HTML and PDF exports)
# ---------------------------------------------------------------------

def _classify_shodan_status(shodan_info):
    if "error" not in shodan_info:
        return "Active"
    message = (shodan_info.get("error") or "").lower()
    if "not configured" in message:
        return "API Key Missing"
    if "no shodan data" in message:
        return "No Data Found"
    if "invalid api key" in message or "access denied" in message:
        return "Access Denied"
    if "dns resolution failed" in message:
        return "Resolution Failed"
    if "invalid ip" in message:
        return "Invalid IP"
    if "query limit" in message:
        return "Query Limit Exceeded"
    if "timeout" in message:
        return "Timeout"
    if "connection error" in message:
        return "Connection Error"
    return "Unavailable"


def _classify_ssl_status(ssl_info):
    if "error" in ssl_info:
        return "Unavailable"
    common_name = ssl_info.get("common_name")
    if not common_name or common_name == NOT_FOUND:
        return "No Certificate Found"
    valid_until = ssl_info.get("valid_until")
    if valid_until and valid_until != NOT_FOUND:
        try:
            parsed = datetime.strptime(valid_until, CRTSH_DATETIME_FORMAT)
            return "Valid" if parsed >= datetime.utcnow() else "Expired"
        except (ValueError, TypeError):
            pass
    return "Valid"


def _compute_summary(report):
    """
    Compute the same Executive Summary fields shown on the live
    dashboard's OSINT Summary card, from the aggregated report dict.
    """
    domain = report.get("domain", "")
    whois = report.get("whois", {}) or {}
    dns = report.get("dns", {}) or {}
    ssl_info = report.get("ssl", {}) or {}
    shodan_info = report.get("shodan", {}) or {}
    email_info = report.get("email", {}) or {}
    subdomains_info = report.get("subdomains", {}) or {}

    resolved_ip = NOT_FOUND
    dns_a = dns.get("A") if "error" not in dns else None
    if isinstance(dns_a, list) and dns_a:
        resolved_ip = dns_a[0]
    elif "error" not in shodan_info and shodan_info.get("ip"):
        resolved_ip = shodan_info["ip"]

    registrar = "Unavailable" if "error" in whois else _display(whois.get("registrar"))
    country = "Unavailable" if "error" in whois else _display(whois.get("country"))

    subdomain_count = len(subdomains_info.get("subdomains") or []) if "error" not in subdomains_info else 0
    email_count = len(email_info.get("emails") or []) if "error" not in email_info else 0

    return {
        "domain": domain,
        "resolved_ip": resolved_ip,
        "registrar": registrar,
        "country": country,
        "ssl_status": _classify_ssl_status(ssl_info),
        "shodan_status": _classify_shodan_status(shodan_info),
        "subdomain_count": subdomain_count,
        "email_count": email_count,
    }


# ---------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------

def build_html_report(report):
    """
    Build a standalone, self-contained HTML document (inline CSS, no
    external assets) presenting the full reconnaissance report for
    download.

    Args:
        report (dict): The report dict (same shape produced by
            modules.report_generator.generate_report()).

    Returns:
        str: A complete HTML document as a string.
    """
    domain = _escape_html(report.get("domain", ""))
    whois = report.get("whois", {}) or {}
    dns = report.get("dns", {}) or {}
    subdomains = report.get("subdomains", {}) or {}
    ssl_info = report.get("ssl", {}) or {}
    shodan_info = report.get("shodan", {}) or {}
    email_info = report.get("email", {}) or {}
    social = report.get("social", {}) or {}
    summary = _compute_summary(report)

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def section(title, content_html):
        return f"""
        <section class="report-section">
            <h2>{_escape_html(title)}</h2>
            {content_html}
        </section>
        """

    def key_value_table(rows):
        rows_html = "".join(
            f"<tr><th>{_escape_html(label)}</th><td>{_escape_html(_display(value))}</td></tr>"
            for label, value in rows
        )
        return f"<table>{rows_html}</table>"

    summary_html = key_value_table([
        ("Target Domain", summary["domain"]),
        ("Resolved IP", summary["resolved_ip"]),
        ("Registrar", summary["registrar"]),
        ("Country", summary["country"]),
        ("SSL Status", summary["ssl_status"]),
        ("Shodan Status", summary["shodan_status"]),
        ("Total Subdomains Found", summary["subdomain_count"]),
        ("Total Emails Found", summary["email_count"]),
    ])

    # WHOIS
    if "error" in whois:
        whois_html = f"<p class='status error'>{_escape_html(whois['error'])}</p>"
    else:
        whois_html = key_value_table([
            ("Registrar", whois.get("registrar")),
            ("Creation Date", whois.get("creation_date")),
            ("Expiry Date", whois.get("expiry_date")),
            ("Organization", whois.get("organization")),
            ("Country", whois.get("country")),
            ("Name Servers", whois.get("name_servers")),
        ])

    # DNS
    if "error" in dns:
        dns_html = f"<p class='status error'>{_escape_html(dns['error'])}</p>"
    else:
        dns_html = key_value_table([
            ("A", dns.get("A")),
            ("AAAA", dns.get("AAAA")),
            ("MX", dns.get("MX")),
            ("TXT", dns.get("TXT")),
            ("NS", dns.get("NS")),
            ("CNAME", dns.get("CNAME")),
            ("SOA", dns.get("SOA")),
        ])

    # Subdomains
    if "error" in subdomains:
        subdomains_html = f"<p class='status error'>{_escape_html(subdomains['error'])}</p>"
    else:
        found = subdomains.get("subdomains") or []
        if found:
            items = "".join(f"<li>{_escape_html(item)}</li>" for item in found)
            subdomains_html = f"<p>Total found: {len(found)}</p><ul class='sub-list'>{items}</ul>"
        else:
            subdomains_html = "<p>No subdomains found.</p>"

    # SSL
    if "error" in ssl_info:
        ssl_html = f"<p class='status error'>{_escape_html(ssl_info['error'])}</p>"
    else:
        ssl_html = key_value_table([
            ("Common Name", ssl_info.get("common_name")),
            ("Issuer", ssl_info.get("issuer")),
            ("Valid From", ssl_info.get("valid_from")),
            ("Valid Until", ssl_info.get("valid_until")),
        ])

    # Shodan
    if "error" in shodan_info:
        shodan_html = f"<p class='status error'>{_escape_html(shodan_info['error'])}</p>"
    else:
        shodan_html = key_value_table([
            ("IP", shodan_info.get("ip")),
            ("ISP", shodan_info.get("isp")),
            ("Organization", shodan_info.get("organization")),
            ("Open Ports", shodan_info.get("open_ports")),
            ("Operating System", shodan_info.get("operating_system")),
        ])

    # Emails
    if "error" in email_info:
        email_html = f"<p class='status error'>{_escape_html(email_info['error'])}</p>"
    else:
        found_emails = email_info.get("emails") or []
        if found_emails:
            items = "".join(f"<li>{_escape_html(addr)}</li>" for addr in found_emails)
            email_html = f"<p>Total found: {len(found_emails)}</p><ul class='sub-list'>{items}</ul>"
        else:
            email_html = "<p>No public email addresses found.</p>"

    # Social — rendered as action buttons, matching the live dashboard
    if "error" in social:
        social_html = f"<p class='status error'>{_escape_html(social['error'])}</p>"
    else:
        buttons = []
        for label, key in SOCIAL_BUTTON_LABELS:
            url = social.get(key)
            if url and url != NOT_FOUND:
                buttons.append(f"<a class='social-btn' href='{_escape_html(url)}' target='_blank' rel='noopener'>{_escape_html(label)}</a>")
        social_html = f"<div class='social-buttons'>{''.join(buttons)}</div>" if buttons else "<p>Not Found</p>"

    html_document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OSINT Report - {domain}</title>
<style>
    body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; color: #222; margin: 0; padding: 20px; }}
    h1 {{ color: #1a1a2e; }}
    .meta {{ color: #555; margin-bottom: 20px; }}
    .report-section {{ background-color: #ffffff; border: 1px solid #ddd; border-radius: 8px;
                        padding: 20px 24px; margin-bottom: 22px; }}
    .report-section h2 {{ margin-top: 0; color: #1a1a2e; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 12px 10px; border-bottom: 1px solid #eee; vertical-align: top; line-height: 1.5; }}
    th {{ width: 32%; color: #1a1a2e; }}
    ul.sub-list {{ margin: 0; padding-left: 20px; }}
    ul.sub-list li {{ padding: 4px 0; word-break: break-all; }}
    .status.error {{ color: #a33; font-weight: bold; }}
    .social-buttons {{ display: flex; flex-wrap: wrap; gap: 12px; }}
    .social-btn {{ display: inline-block; padding: 10px 20px; background-color: #22314f; color: #ffffff;
                    text-decoration: none; border-radius: 6px; font-weight: 600; }}
</style>
</head>
<body>
    <h1>OSINT Reconnaissance Report</h1>
    <p class="meta">Target Domain: <strong>{domain}</strong> &middot; Generated: {generated_at}</p>

    {section("Executive Summary", summary_html)}
    {section("WHOIS", whois_html)}
    {section("DNS Records", dns_html)}
    {section("Subdomains", subdomains_html)}
    {section("SSL Certificate (Certificate Transparency)", ssl_html)}
    {section("Shodan Lookup", shodan_html)}
    {section("Emails", email_html)}
    {section("Social Footprint", social_html)}
</body>
</html>"""

    return html_document


# ---------------------------------------------------------------------
# PDF report
# ---------------------------------------------------------------------

class ReportPDF(FPDF):
    """FPDF subclass adding a running header (from page 2 onward) and
    a page-number footer, so the export looks like a real report
    rather than a printed webpage."""

    def __init__(self, domain):
        super().__init__(format="A4")
        self._domain = domain
        self.set_auto_page_break(auto=True, margin=25)
        self.set_margins(left=18, top=20, right=18)

    def header(self):
        # Page 1 has its own cover block drawn manually; skip the
        # running header there.
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120, 124, 148)
        self.cell(95, 8, "OSINT Reconnaissance Report")
        self.cell(0, 8, self._domain, align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(220, 220, 220)
        self.set_line_width(0.2)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(140, 140, 140)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


def _usable_width(pdf):
    return pdf.w - pdf.l_margin - pdf.r_margin


def _pdf_section_title(pdf, title):
    pdf.set_fill_color(244, 246, 250)
    pdf.set_text_color(26, 26, 46)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, f"  {title}", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 10)


PDF_TABLE_VALUE_MAX_LENGTH = 250


def _pdf_table_value(value):
    """
    Format a value for display inside a PDF `table` cell, truncating
    long values (e.g. TXT/NS/SOA DNS records) so a single cell can
    never grow tall enough to overflow one page. FPDF's `table()`
    raises ValueError if a row can't fit on a single page, so long
    values must never reach it untruncated.
    """
    text = _display(value)
    if len(text) > PDF_TABLE_VALUE_MAX_LENGTH:
        return text[:PDF_TABLE_VALUE_MAX_LENGTH].rstrip() + "..."
    return text


def _pdf_kv_table(pdf, rows):
    usable = _usable_width(pdf)
    with pdf.table(
        col_widths=(usable * 0.32, usable * 0.68),
        text_align=("LEFT", "LEFT"),
        first_row_as_headings=False,
        line_height=6.5,
        padding=3,
    ) as table:
        for label, value in rows:
            row = table.row()
            row.cell(str(label))
            row.cell(_pdf_table_value(value))


def _pdf_error(pdf, message):
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(163, 52, 31)
    pdf.multi_cell(0, 7, message, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 10)


def _pdf_list_section(pdf, items, empty_message):
    if not items:
        pdf.set_font("Helvetica", "I", 10)
        pdf.multi_cell(0, 7, empty_message, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        return
    pdf.set_font("Helvetica", "B", 10)
    pdf.multi_cell(0, 7, f"Total found: {len(items)}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for item in items:
        pdf.multi_cell(0, 6.5, f"-  {item}", new_x="LMARGIN", new_y="NEXT")


def _pdf_social_buttons(pdf, social):
    usable = _usable_width(pdf)
    gap = 6
    btn_width = (usable - gap) / 2
    btn_height = 11

    x_start = pdf.l_margin
    y_start = pdf.get_y()
    pdf.set_font("Helvetica", "B", 11)

    for index, (label, key) in enumerate(SOCIAL_BUTTON_LABELS):
        url = social.get(key)
        is_clickable = isinstance(url, str) and url.startswith(("http://", "https://"))
        col = index % 2
        row_num = index // 2
        x = x_start + col * (btn_width + gap)
        y = y_start + row_num * (btn_height + gap)
        pdf.set_xy(x, y)
        if is_clickable:
            pdf.set_fill_color(26, 26, 46)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(btn_width, btn_height, label, fill=True, align="C", link=url)
        else:
            pdf.set_fill_color(220, 222, 230)
            pdf.set_text_color(120, 124, 148)
            pdf.cell(btn_width, btn_height, f"{label} (N/A)", fill=True, align="C")

    rows_used = (len(SOCIAL_BUTTON_LABELS) + 1) // 2
    pdf.set_xy(x_start, y_start + rows_used * (btn_height + gap))
    pdf.set_text_color(0, 0, 0)


def build_pdf_report(report):
    """
    Build a professionally formatted PDF report presenting the full
    reconnaissance findings, using the pure-Python `fpdf2` library.

    This function performs NO network lookups — it only formats the
    `report` dict it is given (which the caller may either generate
    fresh via modules.report_generator, or reconstruct from data the
    browser already collected during the live scan, for near-instant
    export generation).

    Args:
        report (dict): The report dict (same shape produced by
            modules.report_generator.generate_report()).

    Returns:
        bytes: The PDF file content.
    """
    domain = report.get("domain", "")
    whois = report.get("whois", {}) or {}
    dns = report.get("dns", {}) or {}
    subdomains = report.get("subdomains", {}) or {}
    ssl_info = report.get("ssl", {}) or {}
    shodan_info = report.get("shodan", {}) or {}
    email_info = report.get("email", {}) or {}
    social = report.get("social", {}) or {}
    summary = _compute_summary(report)

    pdf = ReportPDF(domain)
    pdf.add_page()

    # --- Cover block (page 1 only) ---
    pdf.ln(14)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(26, 26, 46)
    pdf.cell(0, 14, "OSINT Reconnaissance Report", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(69, 80, 122)
    pdf.cell(0, 10, f"Target Domain: {domain}", align="C", new_x="LMARGIN", new_y="NEXT")

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(120, 124, 148)
    pdf.cell(0, 8, f"Scan Date & Time: {generated_at}", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(8)
    pdf.set_draw_color(26, 26, 46)
    pdf.set_line_width(0.8)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(10)
    pdf.set_text_color(0, 0, 0)

    # --- Executive Summary ---
    _pdf_section_title(pdf, "Executive Summary")
    _pdf_kv_table(pdf, [
        ("Target Domain", summary["domain"]),
        ("Resolved IP", summary["resolved_ip"]),
        ("Registrar", summary["registrar"]),
        ("Country", summary["country"]),
        ("SSL Status", summary["ssl_status"]),
        ("Shodan Status", summary["shodan_status"]),
        ("Total Subdomains Found", summary["subdomain_count"]),
        ("Total Emails Found", summary["email_count"]),
    ])
    pdf.ln(6)

    # --- WHOIS ---
    _pdf_section_title(pdf, "WHOIS")
    if "error" in whois:
        _pdf_error(pdf, whois["error"])
    else:
        _pdf_kv_table(pdf, [
            ("Registrar", whois.get("registrar")),
            ("Creation Date", whois.get("creation_date")),
            ("Expiry Date", whois.get("expiry_date")),
            ("Organization", whois.get("organization")),
            ("Country", whois.get("country")),
            ("Name Servers", whois.get("name_servers")),
        ])
    pdf.ln(6)

    # --- DNS Records ---
    _pdf_section_title(pdf, "DNS Records")
    if "error" in dns:
        _pdf_error(pdf, dns["error"])
    else:
        _pdf_kv_table(pdf, [(label, dns.get(label)) for label in ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")])
    pdf.ln(6)

    # --- SSL Certificate ---
    _pdf_section_title(pdf, "SSL Certificate (Certificate Transparency)")
    if "error" in ssl_info:
        _pdf_error(pdf, ssl_info["error"])
    else:
        _pdf_kv_table(pdf, [
            ("Common Name", ssl_info.get("common_name")),
            ("Issuer", ssl_info.get("issuer")),
            ("Valid From", ssl_info.get("valid_from")),
            ("Valid Until", ssl_info.get("valid_until")),
        ])
    pdf.ln(6)

    # --- Shodan ---
    _pdf_section_title(pdf, "Shodan Lookup")
    if "error" in shodan_info:
        _pdf_error(pdf, shodan_info["error"])
    else:
        _pdf_kv_table(pdf, [
            ("IP", shodan_info.get("ip")),
            ("ISP", shodan_info.get("isp")),
            ("Organization", shodan_info.get("organization")),
            ("Open Ports", shodan_info.get("open_ports")),
            ("Operating System", shodan_info.get("operating_system")),
        ])
    pdf.ln(6)

    # --- Emails ---
    _pdf_section_title(pdf, "Emails")
    if "error" in email_info:
        _pdf_error(pdf, email_info["error"])
    else:
        _pdf_list_section(pdf, email_info.get("emails") or [], "No public email addresses found.")
    pdf.ln(6)

    # --- Subdomains ---
    _pdf_section_title(pdf, "Subdomains")
    if "error" in subdomains:
        _pdf_error(pdf, subdomains["error"])
    else:
        _pdf_list_section(pdf, subdomains.get("subdomains") or [], "No subdomains found.")
    pdf.ln(6)

    # --- Social Footprint ---
    _pdf_section_title(pdf, "Social Footprint")
    if "error" in social:
        _pdf_error(pdf, social["error"])
    else:
        _pdf_social_buttons(pdf, social)

    return bytes(pdf.output())