from __future__ import annotations

import json
import os
from pathlib import Path

from flask import Flask, Response, flash, redirect, render_template, request, send_file, url_for

from .reports import build_pdf_report
from .scanner import ScannerEngine
from .scanner.utils import TargetValidationError
from .storage import ScanStore


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("WEBSEC_SECRET_KEY", "dev-only-change-me"),
        DATABASE=str(Path("instance") / "websec_scans.sqlite3"),
        SCAN_TIMEOUT=float(os.environ.get("WEBSEC_SCAN_TIMEOUT", "6")),
        ALLOW_PRIVATE_TARGETS=os.environ.get("WEBSEC_ALLOW_PRIVATE_TARGETS", "1") == "1",
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    store = ScanStore(app.config["DATABASE"])

    @app.get("/")
    def index() -> str:
        return render_template("index.html", scans=store.list_scans())

    @app.post("/scan")
    def scan():
        target_url = request.form.get("target_url", "")
        profile = request.form.get("profile", "standard")
        max_pages = _bounded_int(request.form.get("max_pages"), default=10, minimum=1, maximum=50)
        max_depth = _bounded_int(request.form.get("max_depth"), default=1, minimum=0, maximum=3)
        engine = ScannerEngine(
            timeout=app.config["SCAN_TIMEOUT"],
            allow_private_targets=app.config["ALLOW_PRIVATE_TARGETS"],
            profile=profile,
            max_pages=max_pages,
            max_depth=max_depth,
        )
        try:
            result = engine.scan(target_url)
        except (TargetValidationError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))

        scan_id = store.save_scan(result)
        flash(f"Scan complete: {len(result.findings)} findings.", "success")
        return redirect(url_for("scan_detail", scan_id=scan_id))

    @app.get("/scans/<int:scan_id>")
    def scan_detail(scan_id: int) -> str:
        result = store.get_scan(scan_id)
        if result is None:
            flash("Scan not found.", "error")
            return redirect(url_for("index"))
        return render_template("scan.html", scan_id=scan_id, result=result)

    @app.get("/scans/<int:scan_id>/json")
    def scan_json(scan_id: int) -> Response:
        result = store.get_scan(scan_id)
        if result is None:
            return Response(json.dumps({"error": "not found"}), status=404, mimetype="application/json")
        return Response(json.dumps(result.to_dict(), indent=2), mimetype="application/json")

    @app.get("/scans/<int:scan_id>/pdf")
    def scan_pdf(scan_id: int):
        result = store.get_scan(scan_id)
        if result is None:
            flash("Scan not found.", "error")
            return redirect(url_for("index"))
        pdf_bytes = build_pdf_report(result)
        return send_file(
            path_or_file=__import__("io").BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"websec-scan-{scan_id}.pdf",
        )

    return app


def _bounded_int(raw_value: str | None, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(raw_value or default)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))
