"""
Application configuration.

Loads environment variables from a local .env file (if present) and
exposes the settings needed by the Flask app and reconnaissance
modules (e.g. SHODAN_API_KEY).
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration loaded by the Flask app factory."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    DEBUG = os.environ.get("FLASK_DEBUG", "True") == "True"
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
