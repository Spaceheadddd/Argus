from __future__ import annotations

from typing import List, Optional

from scanner.core.models import Config, Finding, Severity
from scanner.core.requester import Requester
from scanner.utils.crawler import CrawlerData


_HEADER_RULES = {
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "title": "Missing Content-Security-Policy",
        "description": (
            "The Content-Security-Policy header is absent. CSP restricts the sources "
            "from which scripts, styles, and other resources can be loaded, mitigating "
            "XSS and data injection attacks."
        ),
        "remediation": "Add a restrictive CSP header, e.g.: Content-Security-Policy: default-src 'self'",
        "cwe": "CWE-693",
        "owasp": "A05:2021",
    },
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "title": "Missing Strict-Transport-Security (HSTS)",
        "description": (
            "HSTS is not set. Without it, browsers may allow downgrade attacks to HTTP, "
            "exposing traffic to interception."
        ),
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cwe": "CWE-523",
        "owasp": "A02:2021",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "title": "Missing X-Frame-Options (Clickjacking Risk)",
        "description": (
            "Without X-Frame-Options, the page can be embedded in an iframe on an "
            "attacker-controlled site, enabling clickjacking attacks."
        ),
        "remediation": "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors directive)",
        "cwe": "CWE-1021",
        "owasp": "A05:2021",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "title": "Missing X-Content-Type-Options",
        "description": (
            "Without this header, browsers may MIME-sniff responses away from the declared "
            "Content-Type, potentially enabling XSS via uploaded files."
        ),
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "cwe": "CWE-430",
        "owasp": "A05:2021",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "title": "Missing Referrer-Policy",
        "description": (
            "Without a Referrer-Policy, the full URL (including query strings and path) "
            "may be leaked to third parties via the Referer header."
        ),
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
        "owasp": "A01:2021",
    },
    "Permissions-Policy": {
        "severity": Severity.INFO,
        "title": "Missing Permissions-Policy Header",
        "description": (
            "Permissions-Policy controls browser features (camera, microphone, geolocation). "
            "Its absence means features are available by default to all embedded content."
        ),
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "cwe": "CWE-693",
        "owasp": "A05:2021",
    },
}

_SAFE_REFERRER_VALUES = {
    "no-referrer",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "same-origin",
    "no-referrer-when-downgrade",
}

_UNSAFE_CSP_TOKENS = ["unsafe-inline", "unsafe-eval", "* ", "*;", "http:"]


class HeadersCheck:
    NAME = "Security Headers"

    def __init__(self, requester: Requester, config: Config):
        self.requester = requester
        self.config = config

    def run(self, crawler_data: CrawlerData) -> List[Finding]:
        findings: List[Finding] = []
        resp = self.requester.get(crawler_data.base_url)
        if resp is None:
            return findings

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header_name, rule in _HEADER_RULES.items():
            value = headers_lower.get(header_name.lower())
            if value is None:
                findings.append(Finding(
                    check_name=self.NAME,
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    evidence=f"Header '{header_name}' not present in response.",
                    remediation=rule["remediation"],
                    url=crawler_data.base_url,
                    cwe=rule.get("cwe"),
                    owasp=rule.get("owasp"),
                ))
            else:
                weak = self._check_value_quality(header_name, value)
                if weak:
                    findings.append(Finding(
                        check_name=self.NAME,
                        title=f"Weak {header_name} Configuration",
                        severity=Severity.MEDIUM,
                        description=weak,
                        evidence=f"{header_name}: {value}",
                        remediation=rule["remediation"],
                        url=crawler_data.base_url,
                        cwe=rule.get("cwe"),
                        owasp=rule.get("owasp"),
                    ))

        # Information disclosure headers
        for disclose in ("Server", "X-Powered-By"):
            val = headers_lower.get(disclose.lower())
            if val:
                findings.append(Finding(
                    check_name=self.NAME,
                    title=f"Server Information Disclosure via {disclose}",
                    severity=Severity.INFO,
                    description=(
                        f"The '{disclose}' header reveals server software details "
                        "that can help attackers fingerprint the technology stack."
                    ),
                    evidence=f"{disclose}: {val}",
                    remediation=f"Remove or obscure the '{disclose}' header in your server config.",
                    url=crawler_data.base_url,
                    cwe="CWE-200",
                    owasp="A05:2021",
                ))

        return findings

    def _check_value_quality(self, header: str, value: str) -> Optional[str]:
        v = value.lower()
        if header == "Content-Security-Policy":
            issues = [t for t in _UNSAFE_CSP_TOKENS if t.lower() in v]
            if issues:
                return (
                    f"CSP contains unsafe directives: {', '.join(issues)}. "
                    "These weaken the policy and may allow XSS."
                )
        elif header == "Strict-Transport-Security":
            try:
                max_age = int(
                    next(
                        (p.split("=")[1] for p in v.split(";") if "max-age" in p),
                        "0",
                    ).strip()
                )
                if max_age < 31536000:
                    return f"HSTS max-age is {max_age}s (< 1 year). Increase to at least 31536000."
            except (ValueError, StopIteration):
                return "HSTS header is malformed or missing max-age."
        elif header == "X-Frame-Options":
            if v.strip() not in ("deny", "sameorigin"):
                return f"X-Frame-Options value '{value}' is not 'DENY' or 'SAMEORIGIN'."
        elif header == "Referrer-Policy":
            if v.strip() not in _SAFE_REFERRER_VALUES:
                return (
                    f"Referrer-Policy '{value}' may leak URL information. "
                    f"Use one of: {', '.join(_SAFE_REFERRER_VALUES)}"
                )
        return None
