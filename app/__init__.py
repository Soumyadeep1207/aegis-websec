"""Application factory for Aegis WebSec."""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure the Flask application."""
    data_dir = Path(os.environ.get("WEBSEC_DATA_DIR", _default_data_dir()))
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("WEBSEC_SECRET_KEY", "dev-only-change-me"),
        DATABASE=os.environ.get("WEBSEC_DATABASE", str(data_dir / "websec_scans.sqlite3")),
        REPORT_DIR=os.environ.get("WEBSEC_REPORT_DIR", str(data_dir / "reports")),
        SCAN_TIMEOUT=float(os.environ.get("WEBSEC_SCAN_TIMEOUT", "6")),
        ALLOW_PRIVATE_TARGETS=os.environ.get("WEBSEC_ALLOW_PRIVATE_TARGETS", "1") == "1",
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    from .routes import register_routes

    register_routes(app)
    return app


def _default_data_dir() -> str:
    if os.environ.get("VERCEL"):
        return "/tmp/aegis-websec"
    return "instance"


__all__ = ["create_app"]
