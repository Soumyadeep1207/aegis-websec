from app.routes import (
    _compliance_matrix,
    _history_metrics,
    _judge_scorecard,
    _module_health,
    _remediation_sla,
    _remediation_workflow,
    _risk_factors,
    _risk_label,
)


def test_risk_labels_are_judge_friendly():
    assert _risk_label(90) == "Critical Exposure"
    assert _risk_label(70) == "High Risk"
    assert _risk_label(45) == "Moderate Risk"
    assert _risk_label(20) == "Low Risk"
    assert _risk_label(0) == "Strong Baseline"


def test_remediation_sla_tracks_severity():
    assert _remediation_sla("critical") == "24-48 hours"
    assert _remediation_sla("high") == "3-7 days"
    assert _remediation_sla("medium") == "14-30 days"
    assert _remediation_sla("info") == "Track for next review"


def test_history_metrics_include_trend_and_readiness():
    metrics = _history_metrics(
        [
            {"target": "https://target-a.test", "summary": {"risk_score": 50, "grade": "C", "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}, "pdf_path": "report.pdf"},
            {"target": "https://target-b.test", "summary": {"risk_score": 75, "grade": "D", "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}, "pdf_path": None},
        ]
    )

    assert metrics["trend_label"] == "Risk reduced"
    assert metrics["presentation_readiness"] == "Demo-ready"
    assert metrics["serious_findings"] == 1
    assert metrics["portfolio_score"] == 38
    assert metrics["unique_targets"] == 2


def test_judge_scorecard_risk_factors_and_compliance_are_generated():
    scorecard = _judge_scorecard({"coverage": {"Hardening": "Clean"}, "scanned_url_count": 3, "profile": "competition"}, 25, {"Critical": 0})
    factors = _risk_factors({"module_count": 4, "scanned_url_count": 3, "crawled_pages": [], "module_errors": {}}, 25, {"Critical": 0, "High": 1})
    compliance = _compliance_matrix({"Hardening": "Clean"})

    assert len(scorecard) == 5
    assert scorecard[0]["criterion"] == "Technical Depth"
    assert factors[0]["factor"] == "Severity Concentration"
    assert compliance[0]["control"] == "Hardening"


def test_workflow_and_module_health_are_generated():
    workflow = _remediation_workflow({"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5})
    health = _module_health({"module_count": 3, "module_errors": {"XSS": "timeout"}})

    assert workflow[1]["stage"] == "Urgent Fix"
    assert workflow[1]["count"] == 3
    assert health[0]["status"] == "2/3"
    assert health[1]["module"] == "XSS"
