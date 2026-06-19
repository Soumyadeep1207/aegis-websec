from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from .crawler import SameOriginCrawler
from .models import Finding, ScanResult
from .modules import (
    CSPAnalysisModule,
    CookieSecurityModule,
    CORSModule,
    DirectoryEnumerationModule,
    FingerprintModule,
    FormDiscoveryModule,
    MixedContentModule,
    RedirectParameterModule,
    RobotsExposureModule,
    SQLInjectionModule,
    ScanContext,
    SecurityHeadersModule,
    SecurityTxtModule,
    TLSModule,
    XSSModule,
)
from .scoring import SEVERITY_ORDER
from .utils import build_session, is_private_host, normalize_url, validate_not_blocked


class ScannerEngine:
    def __init__(
        self,
        timeout: float = 6.0,
        allow_private_targets: bool = True,
        profile: str = "standard",
        max_pages: int = 10,
        max_depth: int = 1,
        modules: list | None = None,
    ) -> None:
        self.timeout = timeout
        self.allow_private_targets = allow_private_targets
        self.profile = profile if profile in {"quick", "standard", "deep", "competition"} else "standard"
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.modules = modules or self._modules_for_profile(self.profile)

    def _modules_for_profile(self, profile: str) -> list:
        passive = [
            SecurityHeadersModule(),
            CSPAnalysisModule(),
            CookieSecurityModule(),
            CORSModule(),
            TLSModule(),
            FingerprintModule(),
            SecurityTxtModule(),
        ]
        if profile == "quick":
            return passive
        active = [
            SQLInjectionModule(),
            XSSModule(),
            DirectoryEnumerationModule(),
            FormDiscoveryModule(),
        ]
        if profile == "competition":
            return passive + active + [
                RobotsExposureModule(),
                MixedContentModule(),
                RedirectParameterModule(),
            ]
        return passive + active

    def scan(self, raw_url: str) -> ScanResult:
        started_at = datetime.now(timezone.utc)
        target_url = normalize_url(raw_url)
        validate_not_blocked(target_url)
        parsed = urlparse(target_url)

        if parsed.hostname and is_private_host(parsed.hostname) and not self.allow_private_targets:
            raise ValueError("Private and loopback targets are disabled by configuration.")

        session = build_session(self.timeout)
        crawler = SameOriginCrawler(
            timeout=self.timeout,
            max_pages=self.max_pages if self.profile in {"standard", "deep", "competition"} else 1,
            max_depth=self.max_depth if self.profile in {"deep", "competition"} else min(self.max_depth, 1),
        )
        crawled_pages = crawler.crawl(target_url, session)
        scan_urls = tuple(dict.fromkeys([target_url, *[page.url for page in crawled_pages]]))
        context = ScanContext(
            target_url=target_url,
            timeout=self.timeout,
            session=session,
            scan_urls=scan_urls,
            profile=self.profile,
        )
        findings: list[Finding] = []
        module_errors: dict[str, str] = {}

        for module in self.modules:
            try:
                findings.extend(module.run(context))
            except requests.RequestException as exc:
                module_errors[module.name] = str(exc)
            except Exception as exc:
                module_errors[module.name] = f"{type(exc).__name__}: {exc}"

        findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item.severity, 0), -item.cvss, item.module))
        return ScanResult.create(
            target_url=target_url,
            started_at=started_at,
            findings=findings,
            metadata={
                "module_count": len(self.modules),
                "module_errors": module_errors,
                "profile": self.profile,
                "risk_score": self._risk_score(findings),
                "grade": self._grade(findings),
                "coverage": self._coverage(findings),
                "crawled_pages": [page.__dict__ for page in crawled_pages],
                "scanned_url_count": len(scan_urls),
                "ethical_notice": "Only scan systems you own or have explicit permission to test.",
            },
        )

    def _risk_score(self, findings: list[Finding]) -> int:
        if not findings:
            return 0
        weighted = sum(SEVERITY_ORDER.get(finding.severity, 0) * finding.cvss for finding in findings)
        normalized = min(100, round(weighted * 2.5))
        return int(normalized)

    def _grade(self, findings: list[Finding]) -> str:
        score = self._risk_score(findings)
        if score >= 85:
            return "F"
        if score >= 65:
            return "D"
        if score >= 40:
            return "C"
        if score >= 18:
            return "B"
        return "A"

    def _coverage(self, findings: list[Finding]) -> dict[str, str]:
        module_to_domain = {
            "Security Headers": "Hardening",
            "CSP Analysis": "Client-side Defense",
            "Cookie Security": "Session Security",
            "CORS Policy": "API Exposure",
            "TLS Certificate": "Transport",
            "Technology Fingerprint": "Reconnaissance",
            "Security Contact": "Governance",
            "SQL Injection": "Injection",
            "Reflected XSS": "Client-side Defense",
            "Directory Enumeration": "Exposure",
            "Form Discovery": "Authentication Surface",
            "Robots Exposure": "Reconnaissance",
            "Mixed Content": "Transport",
            "Redirect Parameter Review": "Redirect Abuse",
        }
        domains = {domain: "Clean" for domain in module_to_domain.values()}
        for finding in findings:
            domain = module_to_domain.get(finding.module)
            if domain:
                domains[domain] = finding.severity
        return domains
