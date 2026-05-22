from __future__ import annotations

from typing import List
from urllib.parse import urljoin

from scanner.core.models import Config, Finding, Severity
from scanner.core.requester import Requester
from scanner.utils.crawler import CrawlerData
from scanner.utils.payloads import (
    SENSITIVE_PATHS, TRAVERSAL_FILE_PARAMS, TRAVERSAL_PAYLOADS, TRAVERSAL_SIGNATURES,
)


def _detect_traversal_content(text: str) -> bool:
    lower = text.lower()
    return any(sig.lower() in lower for sig in TRAVERSAL_SIGNATURES)


class TraversalCheck:
    NAME = "Path Traversal"

    def __init__(self, requester: Requester, config: Config):
        self.requester = requester
        self.config = config

    def run(self, crawler_data: CrawlerData) -> List[Finding]:
        findings: List[Finding] = []

        # Parameter-based traversal
        for entry in crawler_data.query_params:
            url = entry["url"]
            params = entry["params"]
            for param_name in params:
                if param_name.lower() in TRAVERSAL_FILE_PARAMS:
                    f = self._test_param(url, dict(params), param_name)
                    findings.extend(f)

        # Sensitive file exposure
        for path in SENSITIVE_PATHS:
            full_url = urljoin(crawler_data.base_url, path)
            resp = self.requester.get(full_url, allow_redirects=False)
            if resp is None:
                continue
            if resp.status_code == 200 and len(resp.text) > 10:
                findings.append(Finding(
                    check_name=self.NAME,
                    title=f"Sensitive File Exposed: {path}",
                    severity=Severity.HIGH,
                    description=(
                        f"The file at '{path}' is publicly accessible. "
                        "This may expose credentials, configuration, or source code."
                    ),
                    evidence=f"GET {full_url} → 200 OK ({len(resp.text)} bytes)",
                    remediation=f"Restrict access to '{path}' via server configuration.",
                    url=full_url,
                    cwe="CWE-538",
                    owasp="A01:2021",
                ))

        return findings

    def _test_param(self, url: str, params: dict, param_name: str) -> List[Finding]:
        findings = []
        # Baseline
        baseline_resp = self.requester.get(url, params=params)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for payload in TRAVERSAL_PAYLOADS:
            test_params = {**params, param_name: payload}
            resp = self.requester.get(url, params=test_params)
            if resp is None or resp.status_code >= 400:
                continue
            if _detect_traversal_content(resp.text) and not _detect_traversal_content(baseline_text):
                matched = next(
                    (s for s in TRAVERSAL_SIGNATURES if s.lower() in resp.text.lower()), ""
                )
                findings.append(Finding(
                    check_name=self.NAME,
                    title=f"Path Traversal via Parameter '{param_name}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The parameter '{param_name}' is vulnerable to path traversal. "
                        "An attacker can read arbitrary files from the server filesystem."
                    ),
                    evidence=f"Payload: {payload} → matched: '{matched}'",
                    remediation=(
                        "Validate and sanitise file path inputs. Use allowlists for permitted "
                        "files. Never pass user input directly to filesystem operations."
                    ),
                    url=url, cwe="CWE-22", owasp="A01:2021",
                ))
                break  # Confirmed — stop testing this param
        return findings
