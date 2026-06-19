# Automated Web Security Assessment & Monitoring Platform

A Flask-based educational web security scanner built from the internship PPT specification. It scans authorized targets, maps findings to CVSS-style severities, stores scan history in SQLite, and exports PDF/JSON reports.

## Features

- Flask dashboard with scan form, history, finding details, PDF export, JSON export, CSV exports, methodology page, and readiness report
- Modular scanner engine
- Security header checks
- TLS certificate and HTTPS checks
- Reflected XSS probe for query parameters
- Error-based SQL injection probe for query parameters
- Sensitive path discovery
- Basic form discovery
- SQLite scan persistence
- ReportLab PDF generation
- Pytest test suite
- Quick, standard, and deep scan profiles
- Competition scan profile for presentation-grade demos
- Same-origin crawler with depth and page limits
- Cookie flag checks, CSP weakness analysis, and technology fingerprinting
- CORS, mixed-content, robots.txt, security.txt, and redirect parameter review
- Risk score, A-F security grade, and coverage matrix dashboard
- Portfolio security score, remediation workflow board, effort mix, module health, attack surface inventory, compliance evidence matrix, and readiness API

## Legal and Ethical Use

Only scan systems you own, intentionally vulnerable labs such as DVWA, or public targets where you have explicit permission. Do not use this tool for unauthorized testing.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_server.py
```

Open `http://127.0.0.1:5000`.

If dependencies are already installed in the included virtual environment, run:

```powershell
.\.venv\Scripts\python.exe run_server.py
```

## Public Hosting

This project is ready for cloud hosting on Render, Railway, or any Python WSGI host.

Recommended Render setup:

1. Connect this GitHub repository: `Soumyadeep1207/aegis-websec`
2. Choose **New Web Service**
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn wsgi:app`
5. Add environment variables:
   - `WEBSEC_SECRET_KEY`: generate a secure random value
   - `WEBSEC_ALLOW_PRIVATE_TARGETS`: `0`
   - `WEBSEC_SCAN_TIMEOUT`: `6`
   - `WEBSEC_BLOCKED_DOMAINS`: optional comma-separated blocklist

Render will provide a public URL such as:

```text
https://aegis-websec.onrender.com
```

For a custom domain, add the domain in the Render service settings, then create the DNS record Render shows, usually a `CNAME` from `www` to the Render hostname.

## Reviewer Entrypoints

- Dashboard: `http://127.0.0.1:5000`
- Methodology: `http://127.0.0.1:5000/methodology`
- Readiness report: `http://127.0.0.1:5000/readiness`
- Portfolio API: `http://127.0.0.1:5000/api/portfolio`
- Readiness API: `http://127.0.0.1:5000/api/readiness`
- History CSV: `http://127.0.0.1:5000/history.csv`

## Scan Profiles

- `Quick passive`: headers, cookies, CORS, CSP, TLS, security.txt, and technology fingerprinting
- `Standard`: quick checks plus SQLi, reflected XSS, directory enumeration, forms, and shallow crawling
- `Deep crawl`: standard checks plus deeper same-origin crawling and additional sensitive path probes
- `Competition`: deep crawling plus robots exposure, mixed content, redirect parameter review, executive grade, and coverage matrix

## Recommended Lab Targets

- DVWA running locally
- Metasploitable2 in an isolated network
- OWASP Juice Shop in a local container
- `http://testphp.vulnweb.com` for legal demonstration scans

## Configuration

Environment variables:

- `WEBSEC_SECRET_KEY`: Flask session secret
- `WEBSEC_SCAN_TIMEOUT`: per-request timeout in seconds, default `6`
- `WEBSEC_ALLOW_PRIVATE_TARGETS`: set `0` to block private and loopback targets
- `WEBSEC_BLOCKED_DOMAINS`: optional comma-separated domain blocklist

## Run Tests

```powershell
pytest
```

## CLI Scans

Run individual modules:

```powershell
.\.venv\Scripts\python.exe -m app.cli module sqli "http://testphp.vulnweb.com/listproducts.php?cat=1"
.\.venv\Scripts\python.exe -m app.cli module xss "http://testphp.vulnweb.com/search.php?test=query"
.\.venv\Scripts\python.exe -m app.cli module headers "http://testphp.vulnweb.com"
.\.venv\Scripts\python.exe -m app.cli module directories "http://testphp.vulnweb.com"
```

Run the full competition scan and generate reports:

```powershell
.\.venv\Scripts\python.exe -m app.cli scan "http://testphp.vulnweb.com" --profile competition --max-pages 20 --max-depth 2 --pdf reports\vulnweb-report.pdf --json-out reports\vulnweb-report.json
```

## Project Structure

```text
app/
  scanner/       Scanner engine, modules, models, scoring, URL utilities
  reports/       PDF report generation
  templates/     Flask templates
  static/        Dashboard CSS
  storage.py     SQLite persistence layer
  web.py         Flask app factory and routes
tests/           Unit and web smoke tests
```

## Internship Deliverables Covered

- Week 1: reconnaissance foundation through headers/TLS and safe target handling
- Week 2: vulnerability modules for SQLi, XSS, directory enumeration, TLS, headers
- Week 3: Flask dashboard, CVSS severity mapping, SQLite history, PDF reports
- Week 4: tests, documentation, and presentation-ready project structure
