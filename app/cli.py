from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .reports import build_pdf_report
from .scanner.crawler import SameOriginCrawler
from .scanner.engine import ScannerEngine
from .scanner.models import ScanResult
from .scanner.modules import (
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
from .scanner.scoring import SEVERITY_ORDER
from .scanner.utils import build_session, normalize_url


MODULES = {
    "headers": SecurityHeadersModule,
    "csp": CSPAnalysisModule,
    "cookies": CookieSecurityModule,
    "cors": CORSModule,
    "tls": TLSModule,
    "fingerprint": FingerprintModule,
    "securitytxt": SecurityTxtModule,
    "sqli": SQLInjectionModule,
    "xss": XSSModule,
    "directories": DirectoryEnumerationModule,
    "forms": FormDiscoveryModule,
    "robots": RobotsExposureModule,
    "mixed-content": MixedContentModule,
    "redirects": RedirectParameterModule,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis WebSec command line scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    module_parser = subparsers.add_parser("module", help="Run one scanner module")
    module_parser.add_argument("name", choices=sorted(MODULES))
    module_parser.add_argument("url")
    module_parser.add_argument("--profile", choices=["quick", "standard", "deep", "competition"], default="competition")
    module_parser.add_argument("--max-pages", type=int, default=20)
    module_parser.add_argument("--max-depth", type=int, default=2)
    module_parser.add_argument("--timeout", type=float, default=6.0)
    module_parser.add_argument("--json", action="store_true", help="Print JSON instead of readable text")

    scan_parser = subparsers.add_parser("scan", help="Run a full scan")
    scan_parser.add_argument("url")
    scan_parser.add_argument("--profile", choices=["quick", "standard", "deep", "competition"], default="competition")
    scan_parser.add_argument("--max-pages", type=int, default=20)
    scan_parser.add_argument("--max-depth", type=int, default=2)
    scan_parser.add_argument("--timeout", type=float, default=6.0)
    scan_parser.add_argument("--pdf", type=Path, help="Write a PDF report to this path")
    scan_parser.add_argument("--json-out", type=Path, help="Write JSON results to this path")

    args = parser.parse_args()
    if args.command == "module":
        result = run_module(args)
    else:
        result = run_scan(args)

    print_result(result, as_json=getattr(args, "json", False))


def run_module(args: argparse.Namespace) -> ScanResult:
    target_url = normalize_url(args.url)
    session = build_session(args.timeout)
    crawled_pages = SameOriginCrawler(args.timeout, args.max_pages, args.max_depth).crawl(target_url, session)
    scan_urls = tuple(dict.fromkeys([target_url, *[page.url for page in crawled_pages]]))
    context = ScanContext(
        target_url=target_url,
        timeout=args.timeout,
        session=session,
        scan_urls=scan_urls,
        profile=args.profile,
    )
    module = MODULES[args.name]()
    started_at = datetime.now(timezone.utc)
    findings = module.run(context)
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item.severity, 0), -item.cvss, item.module))
    return ScanResult.create(
        target_url=target_url,
        started_at=started_at,
        findings=findings,
        metadata={
            "profile": args.profile,
            "module": module.name,
            "crawled_pages": [page.__dict__ for page in crawled_pages],
            "scanned_url_count": len(scan_urls),
            "module_errors": {},
        },
    )


def run_scan(args: argparse.Namespace) -> ScanResult:
    engine = ScannerEngine(
        timeout=args.timeout,
        profile=args.profile,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
    )
    result = engine.scan(args.url)

    if args.pdf:
        args.pdf.parent.mkdir(parents=True, exist_ok=True)
        args.pdf.write_bytes(build_pdf_report(result))
        print(f"PDF report written: {args.pdf}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(f"JSON report written: {args.json_out}")

    return result


def print_result(result: ScanResult, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(result.to_dict(), indent=2))
        return

    print()
    print(f"Target: {result.target_url}")
    print(f"Profile: {result.metadata.get('profile', 'competition')}")
    if "module" in result.metadata:
        print(f"Module: {result.metadata['module']}")
    if "risk_score" in result.metadata:
        print(f"Risk score: {result.metadata.get('risk_score')} | Grade: {result.metadata.get('grade')}")
    print(f"URLs scanned: {result.metadata.get('scanned_url_count', 1)}")
    print(f"Findings: {len(result.findings)}")
    print()

    if not result.findings:
        print("No findings detected.")
        return

    for finding in result.findings:
        print(f"[{finding.severity.upper()}] {finding.title} | CVSS {finding.cvss:.1f} | {finding.module}")
        print(f"  URL: {finding.url}")
        print(f"  Evidence: {finding.evidence}")
        print(f"  Fix: {finding.remediation}")
        print()


if __name__ == "__main__":
    main()
