from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

from .models import Finding
from .scoring import severity_from_cvss
from .utils import safe_join


@dataclass(frozen=True)
class ScanContext:
    target_url: str
    timeout: float
    session: requests.Session
    scan_urls: tuple[str, ...]
    profile: str = "standard"


class ScannerModule:
    name = "Base"

    def run(self, context: ScanContext) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        title: str,
        cvss: float,
        description: str,
        evidence: str,
        remediation: str,
        url: str,
    ) -> Finding:
        return Finding(
            module=self.name,
            title=title,
            severity=severity_from_cvss(cvss),
            cvss=cvss,
            description=description,
            evidence=evidence,
            remediation=remediation,
            url=url,
        )


class SecurityHeadersModule(ScannerModule):
    name = "Security Headers"

    REQUIRED_HEADERS = {
        "Content-Security-Policy": (6.1, "Add a restrictive CSP that only allows trusted script, style, image, and frame sources."),
        "Strict-Transport-Security": (5.3, "Enable HSTS after confirming HTTPS is stable for the whole site."),
        "X-Frame-Options": (4.3, "Set X-Frame-Options: DENY/SAMEORIGIN or use CSP frame-ancestors."),
        "X-Content-Type-Options": (3.1, "Set X-Content-Type-Options: nosniff."),
        "Referrer-Policy": (2.6, "Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin."),
        "Permissions-Policy": (2.4, "Disable browser features that the application does not need."),
    }

    def run(self, context: ScanContext) -> list[Finding]:
        response = context.session.get(context.target_url, timeout=context.timeout, allow_redirects=True)
        findings: list[Finding] = []
        headers = {key.lower(): value for key, value in response.headers.items()}
        for header, (score, remediation) in self.REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                findings.append(
                    self.finding(
                        title=f"Missing {header}",
                        cvss=score,
                        description=f"The response does not include the {header} security header.",
                        evidence=f"Checked {response.url}; header was not present.",
                        remediation=remediation,
                        url=response.url,
                    )
                )

        server = response.headers.get("Server")
        if server:
            findings.append(
                self.finding(
                    title="Server version disclosed",
                    cvss=2.1,
                    description="The Server header can reveal technology details useful during reconnaissance.",
                    evidence=f"Server: {escape(server)}",
                    remediation="Suppress or minimize version-bearing server headers at the reverse proxy or app server.",
                    url=response.url,
                )
            )
        return findings


class CookieSecurityModule(ScannerModule):
    name = "Cookie Security"

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        try:
            response = context.session.get(context.target_url, timeout=context.timeout, allow_redirects=True)
        except requests.RequestException:
            return findings

        raw_cookies = response.headers.get("Set-Cookie")
        if not raw_cookies:
            return findings

        lowered = raw_cookies.lower()
        if "httponly" not in lowered:
            findings.append(
                self.finding(
                    title="Cookie missing HttpOnly",
                    cvss=4.2,
                    description="At least one cookie appears to be missing the HttpOnly flag.",
                    evidence="Set-Cookie header did not include HttpOnly.",
                    remediation="Set HttpOnly on session and authentication cookies to reduce script access after XSS.",
                    url=response.url,
                )
            )
        if response.url.startswith("https://") and "secure" not in lowered:
            findings.append(
                self.finding(
                    title="HTTPS cookie missing Secure",
                    cvss=5.4,
                    description="At least one cookie over HTTPS appears to be missing the Secure flag.",
                    evidence="Set-Cookie header did not include Secure.",
                    remediation="Set Secure on cookies that should only travel over HTTPS.",
                    url=response.url,
                )
            )
        if "samesite" not in lowered:
            findings.append(
                self.finding(
                    title="Cookie missing SameSite",
                    cvss=3.7,
                    description="At least one cookie appears to be missing a SameSite attribute.",
                    evidence="Set-Cookie header did not include SameSite.",
                    remediation="Set SameSite=Lax or SameSite=Strict unless cross-site flows are required.",
                    url=response.url,
                )
            )
        return findings


class CSPAnalysisModule(ScannerModule):
    name = "CSP Analysis"

    def run(self, context: ScanContext) -> list[Finding]:
        try:
            response = context.session.get(context.target_url, timeout=context.timeout, allow_redirects=True)
        except requests.RequestException:
            return []
        csp = response.headers.get("Content-Security-Policy", "")
        if not csp:
            return []

        lowered = csp.lower()
        findings: list[Finding] = []
        weak_tokens = ["'unsafe-inline'", "'unsafe-eval'", "http:", "data:"]
        detected = [token for token in weak_tokens if token in lowered]
        if detected:
            findings.append(
                self.finding(
                    title="Weak Content-Security-Policy directive",
                    cvss=4.8,
                    description="The CSP includes directives that weaken browser-side protection.",
                    evidence=f"Weak CSP tokens detected: {', '.join(detected)}",
                    remediation="Remove unsafe-inline/unsafe-eval, prefer nonces or hashes, and restrict sources to trusted HTTPS origins.",
                    url=response.url,
                )
            )
        if "frame-ancestors" not in lowered:
            findings.append(
                self.finding(
                    title="CSP missing frame-ancestors",
                    cvss=3.9,
                    description="The CSP does not define which origins may frame the site.",
                    evidence="frame-ancestors directive was not present.",
                    remediation="Add frame-ancestors 'none' or a strict allowlist to reduce clickjacking risk.",
                    url=response.url,
                )
            )
        return findings


class SQLInjectionModule(ScannerModule):
    name = "SQL Injection"

    PAYLOAD = "' OR '1'='1"
    ERROR_MARKERS = (
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sqlite error",
        "postgresql query failed",
        "odbc sql",
    )

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for scan_url in context.scan_urls:
            parsed = urlparse(scan_url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for key, value in params:
                mutated = [(k, self.PAYLOAD if k == key else v) for k, v in params]
                target = urlunparse(parsed._replace(query=urlencode(mutated)))
                try:
                    response = context.session.get(target, timeout=context.timeout)
                except requests.RequestException:
                    continue
                body = response.text.lower()
                if any(marker in body for marker in self.ERROR_MARKERS):
                    findings.append(
                        self.finding(
                            title=f"Potential SQL injection in '{key}'",
                            cvss=8.6,
                            description="A classic SQL injection payload produced database error output.",
                            evidence=f"Injected parameter '{key}' with {self.PAYLOAD!r} and received SQL error text.",
                            remediation="Use parameterized queries, ORM bind variables, centralized validation, and database least privilege.",
                            url=target,
                        )
                    )
        return findings


class XSSModule(ScannerModule):
    name = "Reflected XSS"

    PAYLOAD = "websec_xss_probe_7f3c"

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for scan_url in context.scan_urls:
            parsed = urlparse(scan_url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for key, value in params:
                mutated = [(k, self.PAYLOAD if k == key else v) for k, v in params]
                target = urlunparse(parsed._replace(query=urlencode(mutated)))
                try:
                    response = context.session.get(target, timeout=context.timeout)
                except requests.RequestException:
                    continue
                if self.PAYLOAD in response.text:
                    findings.append(
                        self.finding(
                            title=f"Potential reflected XSS in '{key}'",
                            cvss=6.1,
                            description="A harmless probe string was reflected in the response body without disappearing through encoding or filtering.",
                            evidence=f"Probe marker {self.PAYLOAD!r} appeared in the HTTP response.",
                            remediation="HTML-encode reflected data by context, validate input, and use CSP as defense in depth.",
                            url=target,
                        )
                    )
        return findings


class DirectoryEnumerationModule(ScannerModule):
    name = "Directory Enumeration"

    PATHS = ("admin", "backup", "config", ".git/HEAD", "robots.txt", "server-status", "phpinfo.php")
    DEEP_PATHS = (
        "admin/login",
        "administrator",
        "debug",
        ".env",
        "wp-admin",
        "api/docs",
        "swagger.json",
        "actuator/health",
    )

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        paths = self.PATHS + (self.DEEP_PATHS if context.profile in {"deep", "competition"} else ())
        for path in paths:
            url = safe_join(context.target_url, path)
            try:
                response = context.session.get(url, timeout=context.timeout, allow_redirects=False)
            except requests.RequestException:
                continue
            if response.status_code in {200, 401, 403}:
                score = 7.2 if path == ".git/HEAD" and response.status_code == 200 else 4.7
                findings.append(
                    self.finding(
                        title=f"Sensitive path exposed: /{path}",
                        cvss=score,
                        description="A common sensitive path returned an interesting status code.",
                        evidence=f"GET {url} returned HTTP {response.status_code}.",
                        remediation="Remove unused files, restrict administrative paths, and block metadata directories at the web server.",
                        url=url,
                    )
                )
        return findings


class CORSModule(ScannerModule):
    name = "CORS Policy"

    def run(self, context: ScanContext) -> list[Finding]:
        try:
            response = context.session.get(
                context.target_url,
                timeout=context.timeout,
                headers={"Origin": "https://attacker.example"},
                allow_redirects=True,
            )
        except requests.RequestException:
            return []

        allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "")
        if allow_origin == "*" and allow_credentials.lower() == "true":
            return [
                self.finding(
                    title="Dangerous CORS wildcard with credentials",
                    cvss=8.1,
                    description="The target allows credentialed cross-origin requests from any origin.",
                    evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
                    remediation="Use a strict origin allowlist and never combine wildcard origins with credentialed requests.",
                    url=response.url,
                )
            ]
        if allow_origin == "*":
            return [
                self.finding(
                    title="Permissive CORS wildcard",
                    cvss=4.6,
                    description="The target allows cross-origin reads from any origin.",
                    evidence="Access-Control-Allow-Origin: *.",
                    remediation="Restrict CORS to trusted origins and only expose APIs that truly need browser cross-origin access.",
                    url=response.url,
                )
            ]
        if allow_origin == "https://attacker.example":
            return [
                self.finding(
                    title="Origin reflection in CORS policy",
                    cvss=7.2,
                    description="The server reflected an untrusted Origin header into Access-Control-Allow-Origin.",
                    evidence="Origin https://attacker.example was reflected in the CORS response.",
                    remediation="Validate requested origins against an allowlist before reflecting them.",
                    url=response.url,
                )
            ]
        return []


class SecurityTxtModule(ScannerModule):
    name = "Security Contact"

    def run(self, context: ScanContext) -> list[Finding]:
        url = safe_join(context.target_url, ".well-known/security.txt")
        try:
            response = context.session.get(url, timeout=context.timeout, allow_redirects=True)
        except requests.RequestException:
            return []
        if response.status_code == 404:
            return [
                self.finding(
                    title="Missing security.txt contact file",
                    cvss=1.8,
                    description="The site does not publish a standard security contact file.",
                    evidence=f"GET {url} returned HTTP 404.",
                    remediation="Publish /.well-known/security.txt with contact, policy, and expiry fields for responsible disclosure.",
                    url=url,
                )
            ]
        if response.status_code == 200 and "contact:" not in response.text.lower():
            return [
                self.finding(
                    title="security.txt missing Contact field",
                    cvss=1.5,
                    description="A security.txt file exists but does not appear to include a Contact field.",
                    evidence="security.txt returned HTTP 200 without a Contact field.",
                    remediation="Add a Contact field following RFC 9116.",
                    url=response.url,
                )
            ]
        return []


class RobotsExposureModule(ScannerModule):
    name = "Robots Exposure"

    INTERESTING_TERMS = ("admin", "backup", "private", "config", "debug", "staging", "secret")

    def run(self, context: ScanContext) -> list[Finding]:
        url = safe_join(context.target_url, "robots.txt")
        try:
            response = context.session.get(url, timeout=context.timeout, allow_redirects=True)
        except requests.RequestException:
            return []
        if response.status_code != 200:
            return []
        lines = [line.strip() for line in response.text.splitlines()]
        exposed = [
            line for line in lines
            if line.lower().startswith("disallow:") and any(term in line.lower() for term in self.INTERESTING_TERMS)
        ]
        if not exposed:
            return []
        return [
            self.finding(
                title="robots.txt reveals sensitive-looking paths",
                cvss=3.4,
                description="robots.txt discloses paths that may help attackers prioritize reconnaissance.",
                evidence="; ".join(exposed[:5]),
                remediation="Do not rely on robots.txt for access control. Move sensitive areas behind authentication and authorization.",
                url=response.url,
            )
        ]


class MixedContentModule(ScannerModule):
    name = "Mixed Content"

    ATTRS = ("src", "href")

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        if not context.target_url.startswith("https://"):
            return findings
        for scan_url in context.scan_urls:
            try:
                response = context.session.get(scan_url, timeout=context.timeout)
            except requests.RequestException:
                continue
            if "text/html" not in response.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            insecure_refs: list[str] = []
            for node in soup.find_all(True):
                for attr in self.ATTRS:
                    value = node.get(attr)
                    if isinstance(value, str) and value.startswith("http://"):
                        insecure_refs.append(value)
            if insecure_refs:
                findings.append(
                    self.finding(
                        title="HTTPS page references insecure HTTP resources",
                        cvss=5.8,
                        description="The page includes HTTP resources that can weaken transport security.",
                        evidence="; ".join(insecure_refs[:5]),
                        remediation="Load scripts, styles, images, and links over HTTPS or remove the insecure references.",
                        url=response.url,
                    )
                )
        return findings


class RedirectParameterModule(ScannerModule):
    name = "Redirect Parameter Review"

    SUSPICIOUS_KEYS = {"next", "url", "redirect", "return", "return_url", "continue", "dest", "destination"}

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for scan_url in context.scan_urls:
            parsed = urlparse(scan_url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            suspicious = [key for key, _ in params if key.lower() in self.SUSPICIOUS_KEYS]
            for key in suspicious:
                mutated = [(k, "https://attacker.example" if k == key else v) for k, v in params]
                target = urlunparse(parsed._replace(query=urlencode(mutated)))
                try:
                    response = context.session.get(target, timeout=context.timeout, allow_redirects=False)
                except requests.RequestException:
                    continue
                location = response.headers.get("Location", "")
                if location.startswith("https://attacker.example"):
                    findings.append(
                        self.finding(
                            title=f"Open redirect via '{key}' parameter",
                            cvss=6.1,
                            description="A redirect-like parameter accepted an external destination.",
                            evidence=f"HTTP {response.status_code} Location: {location}",
                            remediation="Allow only relative redirects or validate destinations against a strict allowlist.",
                            url=target,
                        )
                    )
        return findings


class TLSModule(ScannerModule):
    name = "TLS Certificate"

    def run(self, context: ScanContext) -> list[Finding]:
        parsed = urlparse(context.target_url)
        if parsed.scheme != "https" or not parsed.hostname:
            return [
                self.finding(
                    title="Target does not use HTTPS",
                    cvss=6.5,
                    description="The target URL was scanned over HTTP, which exposes traffic to interception and tampering.",
                    evidence=f"Scheme: {parsed.scheme}",
                    remediation="Redirect all traffic to HTTPS and use a valid TLS certificate.",
                    url=context.target_url,
                )
            ]

        port = parsed.port or 443
        findings: list[Finding] = []
        try:
            ssl_context = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, port), timeout=context.timeout) as sock:
                with ssl_context.wrap_socket(sock, server_hostname=parsed.hostname) as wrapped:
                    cert = wrapped.getpeercert()
                    expires_raw = cert.get("notAfter")
        except ssl.SSLError as exc:
            return [
                self.finding(
                    title="TLS certificate validation failed",
                    cvss=7.4,
                    description="The TLS certificate could not be validated by the scanner.",
                    evidence=str(exc),
                    remediation="Install a trusted certificate with the correct hostname and complete chain.",
                    url=context.target_url,
                )
            ]
        except OSError as exc:
            return [
                self.finding(
                    title="TLS connection failed",
                    cvss=4.0,
                    description="The scanner could not complete a TLS connection to the host.",
                    evidence=str(exc),
                    remediation="Verify firewall, DNS, port exposure, and certificate service configuration.",
                    url=context.target_url,
                )
            ]

        if expires_raw:
            expires = datetime.strptime(expires_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(
                    self.finding(
                        title="TLS certificate expired",
                        cvss=7.4,
                        description="The certificate has expired and clients may reject the site.",
                        evidence=f"Certificate expired on {expires.date().isoformat()}.",
                        remediation="Renew and deploy the certificate immediately.",
                        url=context.target_url,
                    )
                )
            elif days_left <= 30:
                findings.append(
                    self.finding(
                        title="TLS certificate expires soon",
                        cvss=3.7,
                        description="The certificate is close to expiry.",
                        evidence=f"Certificate expires in {days_left} days.",
                        remediation="Renew the certificate before expiry and monitor renewal automation.",
                        url=context.target_url,
                    )
                )
        return findings


class FormDiscoveryModule(ScannerModule):
    name = "Form Discovery"

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for scan_url in context.scan_urls:
            try:
                response = context.session.get(scan_url, timeout=context.timeout)
            except requests.RequestException:
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.find_all("form"):
                method = (form.get("method") or "get").lower()
                action = form.get("action") or scan_url
                has_password = form.find("input", {"type": "password"}) is not None
                if method == "get":
                    findings.append(
                        self.finding(
                            title="GET form may expose submitted data",
                            cvss=2.7,
                            description="A form submits with GET, which can place values into URLs, logs, history, and referrers.",
                            evidence=f"Form action: {action}",
                            remediation="Use POST for sensitive submissions and apply CSRF protection to state-changing actions.",
                            url=response.url,
                        )
                    )
                if has_password and response.url.startswith("http://"):
                    findings.append(
                        self.finding(
                            title="Password form served over HTTP",
                            cvss=7.1,
                            description="A password field was found on a page loaded without HTTPS.",
                            evidence=f"Password input detected in form action: {action}",
                            remediation="Serve authentication pages only over HTTPS and redirect HTTP requests.",
                            url=response.url,
                        )
                    )
        return findings


class FingerprintModule(ScannerModule):
    name = "Technology Fingerprint"

    def run(self, context: ScanContext) -> list[Finding]:
        try:
            response = context.session.get(context.target_url, timeout=context.timeout, allow_redirects=True)
        except requests.RequestException:
            return []
        headers = response.headers
        evidence: list[str] = []
        for header in ("Server", "X-Powered-By", "X-AspNet-Version", "Via"):
            value = headers.get(header)
            if value:
                evidence.append(f"{header}: {value}")
        if not evidence:
            return []
        return [
            self.finding(
                title="Technology details exposed in headers",
                cvss=2.2,
                description="Response headers reveal server or framework details that can support targeted reconnaissance.",
                evidence="; ".join(evidence),
                remediation="Minimize version-bearing headers at the application server, framework, or reverse proxy.",
                url=response.url,
            )
        ]
