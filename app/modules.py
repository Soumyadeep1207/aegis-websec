"""Detection-only scanner modules that return finding dictionaries for tests and CLI compatibility."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests


CVSS_SCORES = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}


def cvss_for_severity(severity: str) -> float:
    """Return the manual CVSS score mapped to a severity label."""
    return CVSS_SCORES[severity.lower()]


def make_finding(title: str, severity: str, description: str, affected: str, recommendation: str) -> dict:
    """Create one normalized finding dictionary."""
    return {
        "title": title,
        "severity": severity.lower(),
        "description": description,
        "affected": affected,
        "recommendation": recommendation,
        "cvss": cvss_for_severity(severity),
    }


class HeaderChecker:
    """Check whether important browser security headers are present."""

    REQUIRED_HEADERS = {
        "Content-Security-Policy": "Add a restrictive Content-Security-Policy header.",
        "Strict-Transport-Security": "Enable HSTS after HTTPS is fully deployed.",
        "X-Frame-Options": "Set X-Frame-Options or CSP frame-ancestors.",
        "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff.",
        "Referrer-Policy": "Set a privacy-conscious Referrer-Policy.",
        "Permissions-Policy": "Restrict unused browser features with Permissions-Policy.",
    }

    def run(self, target: str) -> list[dict]:
        """Run the header check and return finding dictionaries."""
        try:
            response = requests.get(target, timeout=6, allow_redirects=True)
        except requests.RequestException as exc:
            return [
                make_finding(
                    "Header check failed",
                    "info",
                    f"The scanner could not fetch the target: {exc}",
                    target,
                    "Verify network connectivity and retry the scan.",
                )
            ]
        headers = {key.lower(): value for key, value in response.headers.items()}
        findings = []
        for header, recommendation in self.REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                findings.append(
                    make_finding(
                        f"Missing {header}",
                        "medium",
                        f"The response does not include the {header} security header.",
                        response.url,
                        recommendation,
                    )
                )
        return findings


class SQLiDetector:
    """Detect basic error-based SQL injection signals in query parameters."""

    PAYLOAD = "' OR '1'='1"
    ERROR_MARKERS = (
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sqlite error",
        "postgresql query failed",
    )

    def run(self, target: str) -> list[dict]:
        """Inject a harmless probe into query parameters and inspect response text."""
        parsed = urlparse(target)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return [
                make_finding(
                    "No query parameters to test",
                    "info",
                    "SQL injection testing needs at least one URL query parameter.",
                    target,
                    "Provide a URL with parameters, for example /page.php?id=1.",
                )
            ]
        findings = []
        for key, value in params:
            mutated = [(k, self.PAYLOAD if k == key else v) for k, v in params]
            probe_url = urlunparse(parsed._replace(query=urlencode(mutated)))
            try:
                response = requests.get(probe_url, timeout=6)
            except requests.RequestException:
                continue
            body = response.text.lower()
            if any(marker in body for marker in self.ERROR_MARKERS):
                findings.append(
                    make_finding(
                        f"Potential SQL injection in '{key}'",
                        "critical",
                        "A SQL injection probe produced database error text in the response.",
                        probe_url,
                        "Use parameterized queries, input validation, and database least privilege.",
                    )
                )
        return findings


class XSSDetector:
    """Detect reflected XSS by checking whether a marker is reflected."""

    MARKER = "aegis_xss_marker_9f31"

    def run(self, target: str) -> list[dict]:
        """Inject a marker into query parameters and inspect response text."""
        parsed = urlparse(target)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return []
        findings = []
        for key, value in params:
            mutated = [(k, self.MARKER if k == key else v) for k, v in params]
            probe_url = urlunparse(parsed._replace(query=urlencode(mutated)))
            try:
                response = requests.get(probe_url, timeout=6)
            except requests.RequestException:
                continue
            if self.MARKER in response.text:
                findings.append(
                    make_finding(
                        f"Potential reflected XSS in '{key}'",
                        "high",
                        "A probe marker was reflected in the HTML response.",
                        probe_url,
                        "Encode reflected output by context and use CSP as defense in depth.",
                    )
                )
        return findings


class SSLChecker:
    """Check whether a target uses HTTPS."""

    def run(self, target: str) -> list[dict]:
        """Return a high severity finding for non-HTTPS URLs."""
        if not target.lower().startswith("https://"):
            return [
                make_finding(
                    "Target does not use HTTPS",
                    "high",
                    "The target URL uses HTTP, exposing traffic to interception and tampering.",
                    target,
                    "Redirect all HTTP traffic to HTTPS and deploy a valid TLS certificate.",
                )
            ]
        return []
