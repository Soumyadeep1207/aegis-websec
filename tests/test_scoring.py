from app.scanner.scoring import severity_from_cvss


def test_severity_from_cvss_boundaries():
    assert severity_from_cvss(9.0) == "Critical"
    assert severity_from_cvss(7.0) == "High"
    assert severity_from_cvss(4.0) == "Medium"
    assert severity_from_cvss(0.1) == "Low"
    assert severity_from_cvss(0.0) == "Info"
