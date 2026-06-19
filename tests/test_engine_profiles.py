from app.scanner.engine import ScannerEngine


def test_quick_profile_uses_passive_modules():
    engine = ScannerEngine(profile="quick")
    names = [module.name for module in engine.modules]

    assert "Security Headers" in names
    assert "Cookie Security" in names
    assert "SQL Injection" not in names


def test_unknown_profile_falls_back_to_standard():
    engine = ScannerEngine(profile="unknown")

    assert engine.profile == "standard"


def test_competition_profile_includes_showcase_modules():
    engine = ScannerEngine(profile="competition")
    names = [module.name for module in engine.modules]

    assert "Robots Exposure" in names
    assert "Mixed Content" in names
    assert "Redirect Parameter Review" in names
