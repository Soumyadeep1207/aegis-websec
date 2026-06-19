from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Finding:
    module: str
    title: str
    severity: str
    cvss: float
    description: str
    evidence: str
    remediation: str
    url: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    target_url: str
    started_at: str
    finished_at: str
    findings: list[Finding]
    metadata: dict[str, Any]

    @classmethod
    def create(
        cls,
        target_url: str,
        started_at: datetime,
        findings: list[Finding],
        metadata: dict[str, Any],
    ) -> "ScanResult":
        return cls(
            target_url=target_url,
            started_at=started_at.astimezone(timezone.utc).isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat(),
            findings=findings,
            metadata=metadata,
        )

    def severity_counts(self) -> dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
            "severity_counts": self.severity_counts(),
        }
