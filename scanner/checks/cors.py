from __future__ import annotations

from typing import List, Optional

from scanner.core.models import Config, Finding, Severity
from scanner.core.requester import Requester
from scanner.utils.crawler import CrawlerData


class CORSCheck:
    NAME = "CORS"

    def __init__(self, requester: Requester, config: Config):
        self.requester = requester
        self.config = config

    def run(self, crawler_data: CrawlerData) -> List[Finding]:
        findings: List[Finding] = []
        url = crawler_data.base_url

        # Baseline response (no injected Origin)
        resp = self.requester.get(url)
        if resp is None:
            return findings

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        # Wildcard ACAO
        if acao == "*":
            severity = Severity.CRITICAL if acac else Severity.MEDIUM
            findings.append(Finding(
                check_name=self.NAME,
                title="CORS Wildcard Origin Allowed"
                       + (" with Credentials" if acac else ""),
                severity=severity,
                description=(
                    "Access-Control-Allow-Origin: * permits any origin to read responses."
                    + (
                        " Combined with Access-Control-Allow-Credentials: true this is a "
                        "critical misconfiguration — browsers reject this combination, but "
                        "some frameworks implement it incorrectly."
                        if acac else ""
                    )
                ),
                evidence=f"ACAO: {acao}" + (f", ACAC: true" if acac else ""),
                remediation="Restrict ACAO to specific trusted origins. Never use * with credentials.",
                url=url, cwe="CWE-942", owasp="A05:2021",
            ))

        # Reflected origin test
        reflected = self._test_origin_reflection(url, "https://evil-attacker.com")
        if reflected:
            findings.append(reflected)

        # Null origin test
        null_finding = self._test_null_origin(url)
        if null_finding:
            findings.append(null_finding)

        return findings

    def _test_origin_reflection(self, url: str, test_origin: str) -> Optional[Finding]:
        resp = self.requester.get(url, headers={"Origin": test_origin})
        if resp is None:
            return None

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        if acao == test_origin or acao.rstrip("/") == test_origin.rstrip("/"):
            severity = Severity.CRITICAL if acac else Severity.HIGH
            return Finding(
                check_name=self.NAME,
                title="CORS Arbitrary Origin Reflection" + (" with Credentials" if acac else ""),
                severity=severity,
                description=(
                    "The server reflects the attacker-supplied Origin header in ACAO. "
                    "Any website can send authenticated cross-origin requests and read responses."
                    if acac else
                    "The server reflects the attacker-supplied Origin header in ACAO. "
                    "Any website can read unauthenticated cross-origin responses."
                ),
                evidence=f"Sent Origin: {test_origin} → ACAO: {acao}"
                         + (", ACAC: true" if acac else ""),
                remediation="Validate Origin against an explicit allowlist before reflecting it.",
                url=url, cwe="CWE-942", owasp="A05:2021",
            )
        return None

    def _test_null_origin(self, url: str) -> Optional[Finding]:
        resp = self.requester.get(url, headers={"Origin": "null"})
        if resp is None:
            return None

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        if acao == "null":
            return Finding(
                check_name=self.NAME,
                title="CORS Null Origin Allowed",
                severity=Severity.HIGH,
                description=(
                    "The server accepts Origin: null, which can be sent by sandboxed iframes, "
                    "local files, and redirected requests — enabling attacks from these contexts."
                ),
                evidence=f"Sent Origin: null → ACAO: {acao}" + (", ACAC: true" if acac else ""),
                remediation="Remove 'null' from the allowed origins list.",
                url=url, cwe="CWE-942", owasp="A05:2021",
            )
        return None
