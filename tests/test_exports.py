"""Tests for scan export routes."""

from pathlib import Path

from app import create_app
from app.models import save_scan, update_scan_pdf


def test_json_export_route(tmp_path):
    """Stored scans should be exportable as JSON."""
    db_path = tmp_path / "test.sqlite3"
    app = create_app({"TESTING": True, "DATABASE": str(db_path), "REPORT_DIR": str(tmp_path / "reports")})
    scan_id = save_scan(
        db_path,
        "http://target",
        "2026-05-21T00:00:00+00:00",
        {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "grade": "B"},
        [{"title": "Finding", "severity": "high", "description": "Desc", "affected": "http://target", "recommendation": "Fix", "cvss": 7.5}],
    )

    response = app.test_client().get(f"/api/scan/{scan_id}")

    assert response.status_code == 200
    assert response.json["target"] == "http://target"


def test_pdf_download_route_resolves_relative_path(tmp_path, monkeypatch):
    """PDF downloads should work for stored relative report paths."""
    db_path = tmp_path / "test.sqlite3"
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    pdf_path = reports_dir / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\n%test")
    monkeypatch.chdir(tmp_path)
    app = create_app({"TESTING": True, "DATABASE": str(db_path), "REPORT_DIR": str(reports_dir)})
    scan_id = save_scan(
        db_path,
        "http://target",
        "2026-05-21T00:00:00+00:00",
        {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "grade": "A"},
        [],
    )
    update_scan_pdf(db_path, scan_id, str(Path("reports") / "report.pdf"))

    response = app.test_client().get(f"/download/{scan_id}")

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"


def test_portfolio_and_csv_exports(tmp_path):
    db_path = tmp_path / "test.sqlite3"
    app = create_app({"TESTING": True, "DATABASE": str(db_path), "REPORT_DIR": str(tmp_path / "reports")})
    save_scan(
        db_path,
        "http://target",
        "2026-05-21T00:00:00+00:00",
        {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "grade": "B", "risk_score": 50},
        [],
    )
    client = app.test_client()

    portfolio = client.get("/api/portfolio")
    csv_response = client.get("/history.csv")

    assert portfolio.status_code == 200
    assert portfolio.json["metrics"]["total_scans"] == 1
    assert csv_response.status_code == 200
    assert csv_response.mimetype == "text/csv"
    assert b"http://target" in csv_response.data


def test_findings_csv_export(tmp_path):
    db_path = tmp_path / "test.sqlite3"
    app = create_app({"TESTING": True, "DATABASE": str(db_path), "REPORT_DIR": str(tmp_path / "reports")})
    scan_id = save_scan(
        db_path,
        "http://target",
        "2026-05-21T00:00:00+00:00",
        {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "grade": "B", "risk_score": 50},
        [
            {
                "title": "Finding",
                "severity": "high",
                "description": "Desc",
                "affected": "http://target",
                "recommendation": "Fix",
                "cvss": 7.5,
                "priority": "P1",
                "confidence": "High",
            }
        ],
    )

    response = app.test_client().get(f"/api/scan/{scan_id}/findings.csv")

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert b"Finding" in response.data


def test_readiness_api(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.sqlite3"), "REPORT_DIR": str(tmp_path / "reports")})

    response = app.test_client().get("/api/readiness")

    assert response.status_code == 200
    assert response.json["overall_status"] == "Competition Ready"


def test_methodology_and_readiness_pages(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.sqlite3"), "REPORT_DIR": str(tmp_path / "reports")})
    client = app.test_client()

    methodology = client.get("/methodology")
    readiness = client.get("/readiness")

    assert methodology.status_code == 200
    assert b"Assessment Methodology" in methodology.data
    assert readiness.status_code == 200
    assert b"Competition Ready" in readiness.data
