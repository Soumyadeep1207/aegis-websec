"""Application factory for Aegis WebSec."""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("WEBSEC_SECRET_KEY", "dev-only-change-me"),
        DATABASE=str(Path("instance") / "websec_scans.sqlite3"),
        REPORT_DIR=str(Path("reports").resolve()),
        SCAN_TIMEOUT=float(os.environ.get("WEBSEC_SCAN_TIMEOUT", "6")),
        ALLOW_PRIVATE_TARGETS=os.environ.get("WEBSEC_ALLOW_PRIVATE_TARGETS", "1") == "1",
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    from .routes import register_routes

    register_routes(app)
    return app


__all__ = ["create_app"]
