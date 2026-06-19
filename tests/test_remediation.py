"""Tests for remediation guidance."""

from app.remediation import remediation_for


def test_remediation_for_sqli_has_steps():
    """SQL injection guidance should include actionable fix steps."""
    guidance = remediation_for("SQL Injection", "Potential SQL injection")

    assert "parameterized" in " ".join(guidance["solution_steps"]).lower()
    assert guidance["impact"]
    assert guidance["verification"]
    assert guidance["references"]


def test_remediation_for_unknown_module_has_default():
    """Unknown modules should still receive generic guidance."""
    guidance = remediation_for("Unknown", "Finding")

    assert guidance["solution_steps"]
    assert guidance["references"]
