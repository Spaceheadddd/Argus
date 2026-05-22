from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from scanner.core.models import Config, Finding, Severity
from scanner.core.requester import Requester
from scanner.utils.crawler import CrawlerData

_SENSITIVE_NAMES = {"session", "auth", "token", "user", "id", "jwt", "access", "refresh"}


class CookiesCheck:
    NAME = "Cookie Security"

    def __init__(self, requester: Requester, config: Config):
        self.requester = requester
        self.config = config

    def run(self, crawler_data: CrawlerData) -> List[Finding]:
        findings: List[Finding] = []
        resp = self.requester.get(crawler_data.base_url)
        if resp is None:
            return findings

        is_https = urlparse(crawler_data.base_url).scheme == "https"
        raw_cookies = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else []

        # requests stores multiple Set-Cookie via raw headers
        raw_set_cookies = [
            v for k, v in resp.raw.headers.items() if k.lower() == "set-cookie"
        ] if hasattr(resp, "raw") and hasattr(resp.raw, "headers") else []

        # Fallback: parse from response.cookies
        if not raw_set_cookies:
            for cookie in resp.cookies:
                findings.extend(self._check_cookie_object(cookie, is_https, crawler_data.base_url))
            return findings

        for raw in raw_set_cookies:
            findings.extend(self._check_raw_cookie(raw, is_https, crawler_data.base_url))

        return findings

    def _check_raw_cookie(self, raw: str, is_https: bool, url: str) -> List[Finding]:
        findings = []
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0].strip()
        attrs_lower = [p.lower() for p in parts[1:]]
        is_sensitive = any(s in name.lower() for s in _SENSITIVE_NAMES)

        if is_https and "secure" not in attrs_lower:
            severity = Severity.HIGH if is_sensitive else Severity.MEDIUM
            findings.append(Finding(
                check_name=self.NAME,
                title=f"Cookie '{name}' Missing Secure Flag",
                severity=severity,
                description=(
                    f"The cookie '{name}' does not have the Secure flag set. "
                    "It can be transmitted over unencrypted HTTP connections."
                ),
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation=f"Set the Secure attribute on '{name}': Set-Cookie: {name}=...; Secure",
                url=url, cwe="CWE-614", owasp="A02:2021",
            ))

        if "httponly" not in attrs_lower:
            severity = Severity.MEDIUM if is_sensitive else Severity.LOW
            findings.append(Finding(
                check_name=self.NAME,
                title=f"Cookie '{name}' Missing HttpOnly Flag",
                severity=severity,
                description=(
                    f"The cookie '{name}' does not have the HttpOnly flag. "
                    "JavaScript can read it, enabling cookie theft via XSS."
                ),
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation=f"Add HttpOnly: Set-Cookie: {name}=...; HttpOnly",
                url=url, cwe="CWE-1004", owasp="A02:2021",
            ))

        samesite_attr = next((p for p in attrs_lower if p.startswith("samesite")), None)
        if samesite_attr is None:
            findings.append(Finding(
                check_name=self.NAME,
                title=f"Cookie '{name}' Missing SameSite Attribute",
                severity=Severity.LOW,
                description=(
                    f"Cookie '{name}' has no SameSite attribute, making it vulnerable "
                    "to cross-site request forgery (CSRF) attacks."
                ),
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation=f"Add SameSite=Lax or SameSite=Strict: Set-Cookie: {name}=...; SameSite=Lax",
                url=url, cwe="CWE-352", owasp="A01:2021",
            ))
        elif "samesite=none" in samesite_attr and "secure" not in attrs_lower:
            findings.append(Finding(
                check_name=self.NAME,
                title=f"Cookie '{name}' SameSite=None Without Secure",
                severity=Severity.MEDIUM,
                description=(
                    "SameSite=None requires the Secure flag. Without it, the cookie "
                    "is rejected by modern browsers or transmitted insecurely."
                ),
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation=f"Set both SameSite=None and Secure: Set-Cookie: {name}=...; SameSite=None; Secure",
                url=url, cwe="CWE-614", owasp="A02:2021",
            ))

        return findings

    def _check_cookie_object(self, cookie, is_https: bool, url: str) -> List[Finding]:
        findings = []
        name = cookie.name
        is_sensitive = any(s in name.lower() for s in _SENSITIVE_NAMES)

        if is_https and not cookie.secure:
            severity = Severity.HIGH if is_sensitive else Severity.MEDIUM
            findings.append(Finding(
                check_name=self.NAME,
                title=f"Cookie '{name}' Missing Secure Flag",
                severity=severity,
                description=f"Cookie '{name}' lacks the Secure flag.",
                evidence=f"Cookie name: {name}",
                remediation=f"Set the Secure attribute on cookie '{name}'.",
                url=url, cwe="CWE-614", owasp="A02:2021",
            ))

        return findings
