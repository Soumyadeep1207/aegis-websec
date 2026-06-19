"""Remediation guidance for Aegis WebSec findings."""

from __future__ import annotations


DEFAULT_GUIDANCE = {
    "impact": "This issue can increase application risk and should be reviewed by the development or security team.",
    "solution_steps": [
        "Confirm the finding manually in an authorized test environment.",
        "Identify the affected code, route, server rule, or deployment configuration.",
        "Apply the recommended security control.",
        "Retest the exact affected URL and run a full regression scan.",
    ],
    "verification": "Run the scanner again and confirm the finding no longer appears.",
    "references": ["https://owasp.org/www-project-top-ten/"],
}


GUIDANCE = {
    "SQL Injection": {
        "impact": "Attackers may read, modify, or delete database records, bypass authentication, or execute unauthorized queries.",
        "solution_steps": [
            "Replace string-concatenated SQL with parameterized queries or ORM bind parameters.",
            "Validate and normalize user input before it reaches database code.",
            "Use least-privilege database accounts for the web application.",
            "Disable verbose database error messages in production responses.",
            "Add unit tests for malicious payloads such as quotes, boolean conditions, and comment markers.",
        ],
        "verification": "Retest the affected parameter with SQL payloads and confirm no SQL errors or logic changes appear.",
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "Reflected XSS": {
        "impact": "Attackers may execute JavaScript in a victim browser, steal session data, or perform actions as the user.",
        "solution_steps": [
            "HTML-encode reflected values based on output context.",
            "Validate input length, type, and expected characters.",
            "Avoid directly inserting user input into HTML, JavaScript, CSS, or URL contexts.",
            "Add a restrictive Content-Security-Policy as defense in depth.",
            "Write regression tests for reflected payload markers.",
        ],
        "verification": "Retest the affected parameter and confirm the payload is encoded or removed, not executed or reflected raw.",
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "Security Headers": {
        "impact": "Missing browser security headers weaken protection against clickjacking, MIME sniffing, data leakage, and script injection.",
        "solution_steps": [
            "Add missing headers at the reverse proxy, web server, or Flask middleware layer.",
            "Start with safe defaults: X-Content-Type-Options: nosniff and Referrer-Policy: strict-origin-when-cross-origin.",
            "Use X-Frame-Options or CSP frame-ancestors to reduce clickjacking risk.",
            "Deploy Content-Security-Policy in report-only mode first, then enforce it after testing.",
            "For HTTPS sites, enable HSTS after confirming all subresources work over HTTPS.",
        ],
        "verification": "Reload the affected URL and confirm the missing header appears in the HTTP response.",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        ],
    },
    "TLS Certificate": {
        "impact": "Weak or missing HTTPS exposes traffic to interception, tampering, and credential theft.",
        "solution_steps": [
            "Install a valid certificate from a trusted certificate authority.",
            "Redirect HTTP requests to HTTPS.",
            "Disable old TLS versions and weak cipher suites.",
            "Enable HSTS only after HTTPS is stable for the whole site.",
            "Monitor certificate expiry and automate renewal.",
        ],
        "verification": "Open the target with HTTPS and confirm the browser shows a valid secure connection.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
        ],
    },
    "Directory Enumeration": {
        "impact": "Exposed administrative, backup, debug, or metadata paths can reveal sensitive files or entry points.",
        "solution_steps": [
            "Remove unused backup, debug, and test files from the web root.",
            "Block access to metadata folders such as .git at the web server.",
            "Require authentication and authorization for administrative routes.",
            "Return consistent 404 or 403 responses for private paths.",
            "Add deployment checks that prevent sensitive files from being published.",
        ],
        "verification": "Request the exposed path again and confirm it is removed, protected, or returns a safe response.",
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    },
    "Cookie Security": {
        "impact": "Weak cookie flags can expose sessions to theft, cross-site leakage, or transmission over insecure channels.",
        "solution_steps": [
            "Set HttpOnly on session cookies.",
            "Set Secure on cookies used over HTTPS.",
            "Set SameSite=Lax or SameSite=Strict unless cross-site behavior is required.",
            "Use short session lifetimes and rotate session identifiers after login.",
        ],
        "verification": "Inspect Set-Cookie headers and confirm HttpOnly, Secure, and SameSite are present where appropriate.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
    },
    "CORS Policy": {
        "impact": "Overly permissive CORS can allow untrusted websites to read API responses from user browsers.",
        "solution_steps": [
            "Replace wildcard origins with an explicit allowlist.",
            "Never combine Access-Control-Allow-Origin: * with credentialed requests.",
            "Validate Origin values server-side before reflecting them.",
            "Restrict allowed methods and headers to what the API actually needs.",
        ],
        "verification": "Send a request with an untrusted Origin and confirm it is not allowed in the CORS response.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
        ],
    },
    "Mixed Content": {
        "impact": "HTTP resources on HTTPS pages can be modified in transit and weaken browser security guarantees.",
        "solution_steps": [
            "Load scripts, styles, images, fonts, and API calls over HTTPS.",
            "Update hardcoded http:// links to https:// where supported.",
            "Use Content-Security-Policy: upgrade-insecure-requests after testing.",
            "Remove third-party resources that do not support HTTPS.",
        ],
        "verification": "Reload the page and confirm browser developer tools show no mixed-content warnings.",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
    },
    "Redirect Parameter Review": {
        "impact": "Open redirects can support phishing, token theft flows, and trust abuse.",
        "solution_steps": [
            "Allow only relative redirect paths.",
            "If external redirects are needed, validate destinations against a strict allowlist.",
            "Reject dangerous schemes and encoded external URLs.",
            "Log rejected redirect attempts for monitoring.",
        ],
        "verification": "Set the redirect parameter to an external domain and confirm the application blocks it.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        ],
    },
}


def remediation_for(module: str, title: str = "") -> dict:
    """Return detailed remediation guidance for a finding."""
    guidance = GUIDANCE.get(module, DEFAULT_GUIDANCE)
    return {
        "impact": guidance["impact"],
        "solution_steps": list(guidance["solution_steps"]),
        "verification": guidance["verification"],
        "references": list(guidance["references"]),
    }
