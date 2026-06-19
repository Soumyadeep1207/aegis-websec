"""Unit tests for detection-only scanner modules."""

from unittest.mock import Mock, patch

from app.modules import HeaderChecker, SQLiDetector, SSLChecker, XSSDetector, cvss_for_severity, make_finding


def fake_response(url: str, text: str = "", headers: dict | None = None) -> Mock:
    """Build a mock requests response."""
    response = Mock()
    response.url = url
    response.text = text
    response.headers = headers or {}
    response.status_code = 200
    return response


def test_make_finding_structure():
    """Verify all required finding keys exist."""
    finding = make_finding("Title", "high", "Description", "http://target", "Fix it")

    assert {"title", "severity", "description", "affected", "recommendation"}.issubset(finding)


@patch("app.modules.requests.get")
def test_header_checker_all_missing(mock_get):
    """Missing security headers should produce six or more findings."""
    mock_get.return_value = fake_response("http://target", headers={})

    findings = HeaderChecker().run("http://target")

    assert len(findings) >= 6


@patch("app.modules.requests.get")
def test_header_checker_all_present(mock_get):
    """All required headers should produce zero header findings."""
    mock_get.return_value = fake_response(
        "https://target",
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        },
    )

    findings = HeaderChecker().run("https://target")

    assert findings == []


@patch("app.modules.requests.get")
def test_sqli_detects_mysql_error(mock_get):
    """MySQL syntax errors should be flagged as critical SQLi evidence."""
    mock_get.return_value = fake_response("http://target/item.php?id=1", "you have an error in your sql syntax")

    findings = SQLiDetector().run("http://target/item.php?id=1")

    assert any(finding["severity"] == "critical" for finding in findings)


def test_sqli_no_params():
    """URLs without query params should return an informational finding."""
    findings = SQLiDetector().run("http://target/items")

    assert findings[0]["severity"] == "info"


@patch("app.modules.requests.get")
def test_xss_detects_reflection(mock_get):
    """Reflected marker should produce a high severity XSS finding."""
    mock_get.return_value = fake_response("http://target/search?q=x", f"hello {XSSDetector.MARKER}")

    findings = XSSDetector().run("http://target/search?q=x")

    assert any(finding["severity"] == "high" for finding in findings)


@patch("app.modules.requests.get")
def test_xss_no_reflection(mock_get):
    """No reflected marker should produce no high severity findings."""
    mock_get.return_value = fake_response("http://target/search?q=x", "safe response")

    findings = XSSDetector().run("http://target/search?q=x")

    assert not any(finding["severity"] == "high" for finding in findings)


def test_ssl_checker_http_site():
    """HTTP targets should be flagged as missing HTTPS."""
    findings = SSLChecker().run("http://target")

    assert findings[0]["severity"] == "high"
    assert "HTTPS" in findings[0]["title"]


def test_cvss_assign_scores():
    """Severity labels should map to manual CVSS v3.1 demo scores."""
    assert cvss_for_severity("critical") == 9.0
    assert cvss_for_severity("high") == 7.5
    assert cvss_for_severity("medium") == 5.0
    assert cvss_for_severity("low") == 2.5
    assert cvss_for_severity("info") == 0.0
