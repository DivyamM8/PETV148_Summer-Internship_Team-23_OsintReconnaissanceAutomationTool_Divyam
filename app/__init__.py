"""
Flask application factory.

Creates the Flask app, loads configuration, and registers blueprints.

Registered so far:
    - main_bp   : homepage, subdomains, ssl, email, social, and
                  full-report endpoints
    - whois_bp  : WHOIS lookup endpoint
    - dns_bp    : DNS enumeration endpoint
    - shodan_bp : Shodan host lookup endpoint
"""

from flask import Flask

from config.config import Config


def create_app():
    """Create and configure the Flask application instance."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Template filter used by report.html to display fields that may
    # be a list, a plain string, or "Not Found".
    @app.template_filter("format_value")
    def format_value_filter(value):
        if isinstance(value, (list, tuple, set)):
            return ", ".join(str(item) for item in value) if value else "Not Found"
        if value in (None, ""):
            return "Not Found"
        return value

    # Register blueprints
    from app.routes.main_routes import main_bp
    from app.routes.whois_routes import whois_bp
    from app.routes.dns_routes import dns_bp
    from app.routes.shodan_routes import shodan_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(whois_bp)
    app.register_blueprint(dns_bp)
    app.register_blueprint(shodan_bp)

    return app
