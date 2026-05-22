from __future__ import annotations

import html
import random
import string
from typing import Dict, List, Optional

from scanner.core.models import Config, Finding, Severity
from scanner.core.requester import Requester
from scanner.utils.crawler import CrawlerData
from scanner.utils.payloads import XSS_PAYLOADS

_DANGEROUS_TAGS = ["<script", "<img", "<svg", "<body", "onerror=", "onload=", "javascript:"]


def _unique_marker() -> str:
    return "ARGUS" + "".join(random.choices(string.digits, k=6))


def _is_reflected(marker: str, payload: str, text: str) -> tuple[bool, str]:
    """Returns (is_reflected, confidence: 'high'|'medium'|'none')"""
    if not text or marker not in text:
        return False, "none"
    # Full payload reflected (unescaped)
    if marker + payload in text or payload in text:
        return True, "high"
    # Marker reflected but payload may be partially stripped
    return True, "medium"


class XSSCheck:
    NAME = "XSS"

    def __init__(self, requester: Requester, config: Config):
        self.requester = requester
        self.config = config

    def run(self, crawler_data: CrawlerData) -> List[Finding]:
        findings: List[Finding] = []

        # URL parameter injection
        for entry in crawler_data.query_params:
            url = entry["url"]
            params = dict(entry["params"])
            for param_name in list(params.keys()):
                f = self._test_url_param(url, params, param_name)
                if f:
                    findings.append(f)

        # Form injection
        for form in crawler_data.forms:
            form_findings = self._test_form(form)
            findings.extend(form_findings)

        return findings

    def _test_url_param(self, url: str, params: dict, param_name: str) -> Optional[Finding]:
        for payload in XSS_PAYLOADS:
            marker = _unique_marker()
            marked = marker + payload
            test_params = {**params, param_name: marked}
            resp = self.requester.get(url, params=test_params)
            if resp is None:
                continue
            reflected, confidence = _is_reflected(marker, payload, resp.text)
            if reflected:
                severity = Severity.HIGH if confidence == "high" else Severity.MEDIUM
                pos = resp.text.find(marker)
                return Finding(
                    check_name=self.NAME,
                    title=f"Reflected XSS via URL Parameter '{param_name}'",
                    severity=severity,
                    description=(
                        f"The parameter '{param_name}' reflects user input back in the "
                        "response without sufficient sanitisation, enabling script injection."
                    ),
                    evidence=(
                        f"Payload reflected {'(full)' if confidence == 'high' else '(partial)'} "
                        f"at position {pos} in response. "
                        f"Payload: {payload[:80]}"
                    ),
                    remediation=(
                        "HTML-encode all user-supplied values before rendering them in responses. "
                        "Use a Content-Security-Policy to restrict script execution."
                    ),
                    url=f"{url}?{param_name}=<payload>",
                    cwe="CWE-79",
                    owasp="A03:2021",
                )
        return None

    def _test_form(self, form: dict) -> List[Finding]:
        findings = []
        testable_fields = [
            f for f in form["fields"]
            if f.get("name") and f.get("type", "text") not in ("submit", "hidden", "file", "button")
        ]

        for field in testable_fields:
            finding = self._test_form_field(form, field["name"])
            if finding:
                findings.append(finding)

        return findings

    def _test_form_field(self, form: dict, field_name: str) -> Optional[Finding]:
        # Build default data with safe values for all other fields
        default_data = {
            f["name"]: f.get("value") or "test"
            for f in form["fields"]
            if f.get("name") and f.get("type") != "file"
        }

        for payload in XSS_PAYLOADS:
            marker = _unique_marker()
            marked = marker + payload
            data = {**default_data, field_name: marked}

            method = form.get("method", "GET").upper()
            if method == "POST":
                resp = self.requester.post(form["action"], data=data)
            else:
                resp = self.requester.get(form["action"], params=data)

            if resp is None:
                continue

            reflected, confidence = _is_reflected(marker, payload, resp.text)
            if reflected:
                severity = Severity.HIGH if confidence == "high" else Severity.MEDIUM
                pos = resp.text.find(marker)
                return Finding(
                    check_name=self.NAME,
                    title=f"Reflected XSS via Form Field '{field_name}'",
                    severity=severity,
                    description=(
                        f"Form field '{field_name}' at {form['action']} reflects input "
                        "without sanitisation."
                    ),
                    evidence=(
                        f"Payload reflected {'(full)' if confidence == 'high' else '(partial)'} "
                        f"at position {pos}. "
                        f"Payload: {payload[:80]}"
                    ),
                    remediation=(
                        "HTML-encode all user-supplied values. "
                        "Implement a restrictive Content-Security-Policy."
                    ),
                    url=form["action"],
                    cwe="CWE-79",
                    owasp="A03:2021",
                )
        return None
