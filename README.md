# Argus — Web Vulnerability Scanner

```
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
  web vulnerability scanner  •  v1.0.0
```

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)

> ⚠️ **Legal Disclaimer:** Argus is intended for use **only** on systems you own or have explicit, written permission to test. Unauthorised scanning may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), or equivalent laws in your jurisdiction. The author accepts no liability for misuse of this tool.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [OWASP Top 10 Coverage](#owasp-top-10-coverage)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [Usage](#usage)
7. [Check Reference](#check-reference)
8. [Output & Reports](#output--reports)
9. [Architecture](#architecture)
10. [Rebranding Guide](#rebranding-guide)
11. [Limitations](#limitations)
12. [Legal & Ethics](#legal--ethics)
13. [Contributing](#contributing)
14. [License](#license)

---

## Overview

**Argus** is a command-line web vulnerability scanner built in Python. Named after the hundred-eyed giant of Greek mythology, it is designed to give you comprehensive visibility into the security posture of a web application — quickly, from a single command.

It crawls the target URL, discovers forms and query parameters, and runs a battery of checks covering the most common web vulnerabilities. Results are printed to the terminal with severity-based colour coding and can optionally be exported to a structured JSON report.

Argus is designed for:
- Penetration testers performing web application assessments
- Developers wanting a fast security sanity-check on their own applications
- Security students and CTF participants learning about web vulnerabilities
- Bug bounty hunters looking for low-hanging fruit

---

## Features

- **8 check modules** covering OWASP Top 10 vulnerability classes
- **Automatic page crawling** — discovers forms, links, and query parameters before testing
- **Severity ratings** — CRITICAL / HIGH / MEDIUM / LOW / INFO with colour-coded output
- **Rich terminal output** — formatted tables, live findings, coloured severity labels
- **JSON report export** (`--output report.json`) for integration with other tools or documentation
- **Rate limiting** (`--delay`) to avoid overwhelming targets or triggering WAFs
- **Verbose mode** (`--verbose`) shows HTTP request/response details and evidence inline
- **Severity filtering** (`--severity-filter`) to surface only the findings you care about
- **Exit codes** — exits with code `1` if HIGH or CRITICAL findings are detected, `0` otherwise (CI-friendly)
- **No-color mode** (`--no-color`) for clean log output in CI pipelines
- **Single-file branding** — all name/identity configuration in one file for easy rebranding

---

## OWASP Top 10 Coverage

| OWASP Category | Check Module | Severity Range |
|---|---|---|
| A01:2021 – Broken Access Control | Path Traversal, Open Redirect | CRITICAL – HIGH |
| A02:2021 – Cryptographic Failures | SSL/TLS, Cookie Security | CRITICAL – LOW |
| A03:2021 – Injection | SQL Injection, XSS | CRITICAL – MEDIUM |
| A05:2021 – Security Misconfiguration | Security Headers, CORS | HIGH – INFO |

---

## Installation

### Prerequisites

- Python 3.9 or higher
- pip

### Option A — Run directly (no install)

```bash
git clone https://github.com/Spaceheadddd/argus.git
cd argus
pip install -r requirements.txt
python3 main.py https://target.com
```

### Option B — Install as a command (`argus`)

```bash
git clone https://github.com/Spaceheadddd/argus.git
cd argus
pip install .
argus https://target.com
```

After installation, the `argus` command is available globally in your shell.

### Option C — Virtual environment (recommended)

```bash
git clone https://github.com/Spaceheadddd/argus.git
cd argus
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python3 main.py https://target.com
```

---

## Quick Start

```bash
# Scan a target with all checks
python3 main.py https://example.com

# Run specific checks only
python3 main.py https://example.com --checks headers,cors,ssl

# Save a JSON report
python3 main.py https://example.com --output report.json

# Verbose scan with a 1-second delay between requests
python3 main.py https://example.com --verbose --delay 1.0

# Only show HIGH and above
python3 main.py https://example.com --severity-filter HIGH
```

**Safe test targets** (intentionally vulnerable, legal to scan):

| Target | Notes |
|---|---|
| `http://testphp.vulnweb.com` | Acunetix test site — SQL injection, XSS, traversal |
| `http://localhost:8080` | Run DVWA locally via Docker |
| `http://localhost:9090` | Run WebGoat locally via Docker |

```bash
# Run DVWA locally
docker run -d -p 8080:80 vulnerables/web-dvwa

# Run WebGoat locally
docker run -d -p 9090:8080 webgoat/goat-and-wolf

python3 main.py http://localhost:8080 --verbose
```

---

## Usage

```
usage: argus [-h] [--checks LIST] [--output FILE] [--verbose] [--delay SECS]
             [--user-agent UA] [--timeout SECS] [--no-color]
             [--severity-filter LEVEL]
             url
```

### Full Options Reference

| Flag | Default | Description |
|---|---|---|
| `url` | *(required)* | Target URL to scan. `https://` is prepended if omitted. |
| `--checks LIST` | all | Comma-separated list of checks to run. See [Check Reference](#check-reference). |
| `--output FILE` / `-o` | None | Write JSON report to FILE. |
| `--verbose` / `-v` | off | Print HTTP request/response details and inline finding evidence. |
| `--delay SECS` | 0.3 | Seconds to wait between HTTP requests. Increase to avoid rate-limiting. |
| `--user-agent UA` | Chrome/120 | Custom User-Agent header value. |
| `--timeout SECS` | 10 | HTTP request timeout in seconds. |
| `--no-color` | off | Disable Rich colour markup (for CI/log files). |
| `--severity-filter LEVEL` | INFO | Only report findings at or above this level. Choices: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no HIGH or CRITICAL findings |
| `1` | HIGH or CRITICAL findings detected (or scan error) |

This makes Argus usable in CI pipelines — a HIGH finding will fail the build.

---

## Check Reference

### Security Headers

**Check name:** `headers`

**What it detects:** Missing or misconfigured HTTP security response headers that leave browsers without important protections.

**How it works:**
Argus makes a single GET request to the target and inspects the response headers. For each expected security header, it checks for presence and validates the value quality. It also flags headers that leak server information.

**Headers checked:**

| Header | Missing Severity | What it does |
|---|---|---|
| `Content-Security-Policy` | HIGH | Restricts resource loading origins, mitigating XSS |
| `Strict-Transport-Security` | HIGH | Forces HTTPS connections, preventing downgrade attacks |
| `X-Frame-Options` | MEDIUM | Prevents clickjacking via iframe embedding |
| `X-Content-Type-Options` | LOW | Prevents MIME-type sniffing |
| `Referrer-Policy` | LOW | Controls URL leakage via Referer header |
| `Permissions-Policy` | INFO | Restricts browser feature access |
| `Server` / `X-Powered-By` | INFO | Flags server version disclosure |

**Example findings:**
```
[HIGH] Missing Content-Security-Policy
[HIGH] Missing Strict-Transport-Security (HSTS)
[MEDIUM] Weak CSP Configuration — contains 'unsafe-inline'
[INFO] Server Information Disclosure via Server: Apache/2.4.41
```

**Remediation example (Nginx):**
```nginx
add_header Content-Security-Policy "default-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

**References:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/), CWE-693, A05:2021

---

### SQL Injection

**Check name:** `sqli`

**What it detects:** Error-based SQL injection vulnerabilities in URL query parameters and HTML form fields.

**How it works:**
1. Argus crawls the target page to collect all URL parameters and form fields.
2. For each parameter, it first captures a **baseline response** (unmodified request).
3. It then injects SQL payloads (e.g. `'`, `' OR 1=1--`, `' UNION SELECT NULL--`) into each parameter.
4. Responses are scanned for database error strings from MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.
5. **False positive guard:** If the error signature already appears in the baseline (e.g. the page always shows "sql error"), it is discarded.
6. Secondary signal: A >50% response size change with a different status code is flagged as a low-confidence potential finding.

**Example SQL error signatures detected:**
- MySQL: `you have an error in your sql syntax`
- MSSQL: `unclosed quotation mark`
- PostgreSQL: `unterminated quoted string at or near`
- Oracle: `ORA-01756`

**Example findings:**
```
[CRITICAL] SQL Injection via URL Parameter 'id'
  Payload: "' OR 1=1--"  →  matched: "you have an error in your sql syntax"
```

**Remediation:**
```python
# Vulnerable:
query = f"SELECT * FROM users WHERE id = {user_input}"

# Safe — use parameterised queries:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))
```

**References:** OWASP Testing Guide — OTG-INPVAL-005, CWE-89, A03:2021

---

### Cross-Site Scripting (XSS)

**Check name:** `xss`

**What it detects:** Reflected XSS vulnerabilities in URL parameters and form fields, where user input is echoed back in the response without proper sanitisation.

**How it works:**
1. For each URL parameter and form field, Argus injects payloads from a curated list (`<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, SVG payloads, etc.).
2. Each payload is prefixed with a **unique random marker** (e.g. `ARGUS938271`) to distinguish injected content from pre-existing page content.
3. If the marker appears in the response, reflection is confirmed.
4. **High confidence** (severity HIGH): the complete payload including HTML tags is reflected unescaped.
5. **Medium confidence** (severity MEDIUM): the marker is reflected but tags appear stripped — partial reflection that may still be exploitable in certain contexts.

**Example findings:**
```
[HIGH] Reflected XSS via URL Parameter 'search'
  Payload reflected (full) at position 4821. Payload: <script>alert(1)</script>

[MEDIUM] Reflected XSS via Form Field 'username'
  Payload reflected (partial) — tags stripped, marker present.
```

**Remediation:**
```python
# Python/Jinja2:
{{ user_input | e }}  # HTML-escape output in templates

# Node.js:
const sanitized = require('he').escape(userInput);

# Content-Security-Policy (defence-in-depth):
Content-Security-Policy: default-src 'self'; script-src 'self'
```

**References:** OWASP XSS Prevention Cheat Sheet, CWE-79, A03:2021

---

### Open Redirect

**Check name:** `open_redirect`

**What it detects:** URL parameters that redirect users to attacker-controlled external domains without validation.

**How it works:**
1. The crawler identifies parameters with names matching common redirect patterns (`url`, `redirect`, `return`, `next`, `goto`, `dest`, etc.).
2. Argus also brute-forces these parameter names on the base URL even if not seen during crawl.
3. For each candidate parameter, it injects payloads pointing to `evil-attacker.com` (`https://evil-attacker.com`, `//evil-attacker.com`, `/\evil-attacker.com`, etc.).
4. Requests are sent with `allow_redirects=False`.
5. If the response is a 3xx and the `Location` header resolves to the external domain, an open redirect is confirmed.

**Example findings:**
```
[HIGH] Open Redirect via Parameter 'return_url'
  GET ?return_url=https://evil-attacker.com → 302 Location: https://evil-attacker.com
```

**Remediation:**
```python
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com", "app.example.com"}

def safe_redirect(url):
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        return "/"  # Redirect to safe default
    return url
```

**References:** OWASP Testing Guide — OTG-CLIENT-004, CWE-601, A01:2021

---

### Path Traversal

**Check name:** `traversal`

**What it detects:**
1. Path traversal vulnerabilities in file-related URL parameters.
2. Publicly accessible sensitive files (`/.git/config`, `/.env`, `/phpinfo.php`, etc.).

**How it works:**
Argus identifies URL parameters with file-related names (`file`, `path`, `page`, `doc`, `template`, `include`, etc.) and injects directory traversal payloads:
- `../etc/passwd`
- `..%2fetc%2fpasswd` (URL-encoded)
- `..%252fetc%252fpasswd` (double-encoded)

Responses are checked for content signatures like `root:x:0:0:` (Linux `/etc/passwd`) or Windows `hosts` file content.

For sensitive file exposure, Argus makes GET requests to common paths and flags any that return `200 OK` with non-trivial content.

**Example findings:**
```
[CRITICAL] Path Traversal via Parameter 'file'
  Payload: ../../../etc/passwd  →  matched: 'root:x:0:0:'

[HIGH] Sensitive File Exposed: /.env
  GET https://target.com/.env → 200 OK (1842 bytes)
```

**Remediation:**
```python
import os

SAFE_BASE = "/var/www/files"

def get_file(user_path):
    # Resolve and confirm path stays within allowed base
    full_path = os.path.realpath(os.path.join(SAFE_BASE, user_path))
    if not full_path.startswith(SAFE_BASE):
        raise ValueError("Path traversal detected")
    return open(full_path).read()
```

**References:** OWASP Testing Guide — OTG-AUTHZ-001, CWE-22, A01:2021

---

### CORS Misconfiguration

**Check name:** `cors`

**What it detects:** Misconfigured Cross-Origin Resource Sharing (CORS) policies that allow arbitrary origins to make authenticated cross-origin requests.

**How it works:**
Argus runs three tests:

1. **Wildcard check:** Inspects the baseline `Access-Control-Allow-Origin` response header. If it is `*`, this is flagged (MEDIUM normally, CRITICAL if combined with `Access-Control-Allow-Credentials: true`).

2. **Origin reflection test:** Sends a request with `Origin: https://evil-attacker.com`. If the server reflects this exact value back in `Access-Control-Allow-Origin`, it means any website can read the response — flagged as HIGH (or CRITICAL with credentials).

3. **Null origin test:** Sends `Origin: null`. If the server allows it, sandboxed iframes and local HTML files can make cross-origin requests — flagged as HIGH.

**Example findings:**
```
[CRITICAL] CORS Arbitrary Origin Reflection with Credentials
  Sent Origin: https://evil-attacker.com → ACAO: https://evil-attacker.com, ACAC: true

[MEDIUM] CORS Wildcard Origin Allowed
  Access-Control-Allow-Origin: *
```

**Remediation:**
```python
# Validate against an explicit allowlist
ALLOWED_ORIGINS = {"https://app.example.com", "https://admin.example.com"}

def set_cors_headers(request, response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    # Never use * with Access-Control-Allow-Credentials: true
```

**References:** OWASP CORS Cheat Sheet, CWE-942, A05:2021

---

### Cookie Security

**Check name:** `cookies`

**What it detects:** Missing or misconfigured security attributes on HTTP cookies, particularly session and authentication cookies.

**How it works:**
Argus makes a GET request to the target and inspects all `Set-Cookie` response headers for the following attributes:

| Attribute | Missing Severity | Risk |
|---|---|---|
| `Secure` | HIGH (sensitive), MEDIUM (other) | Cookie transmitted over HTTP |
| `HttpOnly` | MEDIUM (sensitive), LOW (other) | Cookie readable by JavaScript (XSS theft) |
| `SameSite` | LOW | CSRF vulnerability |
| `SameSite=None` without `Secure` | MEDIUM | Rejected by browsers or sent insecurely |

Cookies with security-sensitive names (`session`, `auth`, `token`, `jwt`, `id`) are flagged at elevated severity.

**Example findings:**
```
[HIGH] Cookie 'sessionid' Missing Secure Flag
[MEDIUM] Cookie 'sessionid' Missing HttpOnly Flag
[LOW] Cookie 'preferences' Missing SameSite Attribute
```

**Remediation:**
```http
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax; Path=/
```

**References:** OWASP Session Management Cheat Sheet, CWE-614, CWE-1004, A02:2021

---

### SSL/TLS Analysis

**Check name:** `ssl`

**What it detects:** Weak or misconfigured TLS configurations including deprecated protocols, weak ciphers, and certificate issues.

**How it works:**
Argus uses Python's stdlib `ssl` and `socket` modules directly (no `requests` dependency) to establish a raw TLS connection and inspect:

1. **Protocol version** — Flags TLS 1.0 and 1.1 as deprecated. TLS 1.2 and 1.3 are acceptable.
2. **Cipher suite** — Flags ciphers containing RC4, DES, 3DES, MD5, NULL, EXPORT, or anonymous (ADH/AECDH) algorithms.
3. **Key length** — Flags cipher key lengths under 128 bits as CRITICAL.
4. **Certificate expiry** — Warns if the certificate expires within 30 days; CRITICAL if already expired.
5. **Self-signed** — Flags certificates where the issuer equals the subject.
6. **Certificate verification errors** — Catches hostname mismatches and invalid chain errors.
7. **Deprecated protocol acceptance** — Actively attempts connections using TLS 1.0 and TLS 1.1 to verify if the server accepts them.

**Example findings:**
```
[CRITICAL] SSL Certificate Has Expired
[HIGH] Server Accepts Deprecated Protocol: TLSv1.1
[HIGH] SSL Certificate Expires Soon (13 days)
[HIGH] Weak Cipher Suite in Use: TLS_RSA_WITH_RC4_128_SHA
```

**Remediation (Nginx):**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;
```

**References:** OWASP Transport Layer Protection Cheat Sheet, CWE-326, CWE-327, A02:2021

---

## Output & Reports

### Terminal Output

Argus uses [Rich](https://github.com/Textualize/rich) for terminal rendering. Findings print live as each check runs, then a full summary table is displayed.

**Severity colour map:**

| Severity | Color | Meaning |
|---|---|---|
| CRITICAL | Bold Red | Immediate exploitation risk |
| HIGH | Red | Significant vulnerability requiring urgent attention |
| MEDIUM | Yellow | Vulnerability with limited exploitability or impact |
| LOW | Cyan | Informational weakness or defence-in-depth gap |
| INFO | Dim White | Noteworthy observation, not directly exploitable |

### JSON Report Schema

When `--output report.json` is used, Argus writes a structured JSON file:

```json
{
  "meta": {
    "tool": "Argus",
    "version": "1.0.0",
    "target": "https://example.com",
    "scan_time": "2026-05-22T18:00:00Z",
    "duration_seconds": 12.4,
    "checks_run": ["headers", "ssl", "cors"],
    "total_findings": 7
  },
  "summary": {
    "CRITICAL": 0,
    "HIGH": 3,
    "MEDIUM": 1,
    "LOW": 2,
    "INFO": 1
  },
  "findings": [
    {
      "id": "FIND-001",
      "check": "Security Headers",
      "title": "Missing Content-Security-Policy",
      "severity": "HIGH",
      "url": "https://example.com",
      "description": "...",
      "evidence": "Header 'Content-Security-Policy' not present in response.",
      "remediation": "Add a restrictive CSP header...",
      "cwe": "CWE-693",
      "owasp": "A05:2021"
    }
  ],
  "errors": []
}
```

---

## Architecture

### Project Structure

```
argus/
├── main.py                      # CLI entrypoint (argparse, exit codes)
├── setup.py                     # Package install + argus console_scripts entry
├── requirements.txt
├── README.md
└── scanner/
    ├── core/
    │   ├── branding.py          # ← All name/identity constants (single source of truth)
    │   ├── models.py            # Finding, ScanResult, Config, Severity dataclasses
    │   ├── requester.py         # Central HTTP client (rate limiting, UA, session)
    │   └── engine.py            # Orchestrates checks, owns the scan lifecycle
    ├── checks/
    │   ├── headers.py           # Security headers audit
    │   ├── ssl_tls.py           # TLS via stdlib socket+ssl
    │   ├── cookies.py           # Cookie flag checks
    │   ├── cors.py              # CORS misconfiguration
    │   ├── open_redirect.py     # Open redirect detection
    │   ├── traversal.py         # Path traversal + sensitive file exposure
    │   ├── xss.py               # Reflected XSS
    │   └── sqli.py              # Error-based SQL injection
    ├── output/
    │   ├── console.py           # Rich terminal renderer
    │   └── reporter.py          # JSON report writer
    └── utils/
        ├── crawler.py           # Link + form discovery (stdlib HTMLParser)
        └── payloads.py          # All payload lists and detection signatures
```

### Module Flow

```
main.py (CLI / argparse)
    │
    └── Engine (core/engine.py)
         ├── Requester (core/requester.py)    rate limiting, UA, shared session
         ├── Crawler (utils/crawler.py)       form + link discovery
         │
         ├── HeadersCheck    (checks/headers.py)
         ├── SSLCheck        (checks/ssl_tls.py)
         ├── CookiesCheck    (checks/cookies.py)
         ├── CORSCheck       (checks/cors.py)
         ├── OpenRedirectCheck (checks/open_redirect.py)
         ├── TraversalCheck  (checks/traversal.py)
         ├── XSSCheck        (checks/xss.py)
         └── SQLiCheck       (checks/sqli.py)
                   │
                   └── Output
                        ├── ConsoleRenderer (output/console.py)
                        └── JSONReporter    (output/reporter.py)
```

### Adding a New Check

Every check module follows the same interface. To add a new check:

1. Create `scanner/checks/my_check.py`:

```python
from scanner.core.models import Config, Finding, Severity
from scanner.core.requester import Requester
from scanner.utils.crawler import CrawlerData

class MyCheck:
    NAME = "My Check"  # Displayed in terminal

    def __init__(self, requester: Requester, config: Config):
        self.requester = requester
        self.config = config

    def run(self, crawler_data: CrawlerData) -> list[Finding]:
        findings = []
        # ... your detection logic ...
        return findings
```

2. Register it in `scanner/core/engine.py`:

```python
from scanner.checks.my_check import MyCheck

CHECK_REGISTRY = {
    # ... existing checks ...
    "my_check": MyCheck,
}
```

That's all. The engine will automatically include it in `--help` and the `--checks` flag.

---

## Rebranding Guide

All branding is centralised in **`scanner/core/branding.py`**. To rename the tool from Argus to something else:

### Step 1 — Edit `scanner/core/branding.py`

```python
TOOL_NAME = "YourToolName"       # Displayed in banner, reports, --help
TOOL_VERSION = "1.0.0"
TOOL_TAGLINE = "web vulnerability scanner"
TOOL_COLOR = "bright_cyan"       # Rich color for ASCII art
ASCII_ART = r"""
... paste your new ASCII art here ...
"""
```

Generate new ASCII art at: https://patorjk.com/software/taag/ (recommended font: ANSI Shadow)

### Step 2 — Update `setup.py`

Change the console_scripts entry:
```python
entry_points={
    "console_scripts": [
        "yourname=main:cli",  # ← change "argus" to your new command name
    ],
},
```

### Step 3 — Reinstall

```bash
pip install -e .
yourname --help
```

### That's it

Every reference to the tool name in the terminal output, JSON reports, and `--help` is pulled from `branding.py`. You do not need to search and replace across the codebase.

---

## Limitations

- **No JavaScript rendering** — Argus uses `requests`, not a headless browser. Dynamic content generated by JavaScript is not tested. Use tools like Burp Suite or ZAP for JS-heavy SPAs.
- **Depth-1 crawl** — Only the landing page is crawled. Links discovered from that page are used for parameter testing but not recursively crawled.
- **Error-based SQLi only** — Blind SQL injection (boolean-based, time-based) is not implemented. Payloads like `AND SLEEP(2)` are sent but timing is not measured.
- **Reflected XSS only** — Stored XSS and DOM-based XSS are not detected.
- **No authentication support** — Argus does not handle login flows, cookies for auth, or OAuth tokens. Test authenticated pages by running Argus with a session cookie added via a proxy.
- **No JavaScript-rendered forms** — Forms created by JavaScript (e.g., React controlled components) are not discovered.
- **Not a replacement for Burp Suite** — Argus is a fast automated check, not a full proxy-based testing tool.

---

## Legal & Ethics

### Authorised Testing Only

Scanning a web application without permission is illegal in most jurisdictions, including:

- **USA:** Computer Fraud and Abuse Act (CFAA) — 18 U.S.C. § 1030
- **UK:** Computer Misuse Act 1990
- **EU:** Directive on Attacks Against Information Systems (2013/40/EU)
- **Australia:** Criminal Code Act 1995

Always obtain **written authorisation** before scanning any system you do not own.

### Safe Testing Environments

| Environment | How to run |
|---|---|
| [DVWA](https://github.com/digininja/DVWA) | `docker run -d -p 8080:80 vulnerables/web-dvwa` |
| [WebGoat](https://owasp.org/www-project-webgoat/) | `docker run -d -p 9090:8080 webgoat/goat-and-wolf` |
| [Vulnhub machines](https://www.vulnhub.com/) | Import OVA into VirtualBox |
| [HackTheBox](https://hackthebox.com) | Legal online labs (subscription) |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Free browser-based labs |
| `testphp.vulnweb.com` | Acunetix public test site |

### Responsible Disclosure

If you discover a vulnerability in a real application using Argus:

1. **Do not exploit it** beyond confirming its existence.
2. Check if the organisation has a **Bug Bounty programme** (HackerOne, Bugcrowd, etc.).
3. If not, contact their security team via `security@domain.com` or their published security policy.
4. Give them reasonable time to fix it (typically 90 days) before public disclosure.

---

## Contributing

Pull requests are welcome. For major changes, open an issue first.

**To add a new check:**
1. Follow the [Adding a New Check](#adding-a-new-check) guide above.
2. Add payloads/signatures to `scanner/utils/payloads.py`.
3. Add test steps to this README's check reference section.
4. Submit a PR with a description of what the check detects and why.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

You are free to use, modify, and distribute this tool. Please include the legal disclaimer in any redistributed version.
