import pytest

from app.scanner.engine import ScannerEngine
from app.scanner.utils import BlockedTargetError, is_blocked_target


def test_no_domains_are_blocked_by_default():
    assert not is_blocked_target("https://vtop.vit.ac.in/vtop/login")
    assert not is_blocked_target("https://jadavpuruniversity.in")


def test_engine_rejects_configured_blocked_domain(monkeypatch):
    from app.scanner import utils

    monkeypatch.setattr(utils, "BLOCKED_DOMAINS", {"blocked.example"})
    engine = ScannerEngine(modules=[])

    with pytest.raises(BlockedTargetError):
        engine.scan("https://blocked.example")
