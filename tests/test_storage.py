from app.scanner.models import Finding, ScanResult
from app.storage import ScanStore


def test_store_round_trip(tmp_path):
    store = ScanStore(tmp_path / "scans.sqlite3")
    result = ScanResult(
        target_url="https://example.test",
        started_at="2026-05-13T00:00:00+00:00",
        finished_at="2026-05-13T00:00:01+00:00",
        metadata={"module_errors": {}},
        findings=[
            Finding(
                module="Unit",
                title="Example finding",
                severity="Low",
                cvss=2.1,
                description="Description",
                evidence="Evidence",
                remediation="Remediation",
                url="https://example.test",
            )
        ],
    )

    scan_id = store.save_scan(result)
    loaded = store.get_scan(scan_id)

    assert loaded is not None
    assert loaded.target_url == result.target_url
    assert loaded.findings[0].title == "Example finding"
