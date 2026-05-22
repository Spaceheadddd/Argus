from __future__ import annotations

from typing import List, Optional

from scanner.core.models import Config, Finding, Severity
from scanner.core.requester import Requester
from scanner.utils.crawler import CrawlerData
from scanner.utils.payloads import SQLI_ERROR_PAYLOADS, SQLI_ERROR_SIGNATURES


def _match_signatures(text: str) -> List[str]:
    lower = text.lower()
    return [sig for sig in SQLI_ERROR_SIGNATURES if sig in lower]


class SQLiCheck:
    NAME = "SQL Injection"

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

        # Form field injection
        for form in crawler_data.forms:
            form_findings = self._test_form(form)
            findings.extend(form_findings)

        return findings

    def _test_url_param(self, url: str, params: dict, param_name: str) -> Optional[Finding]:
        # Baseline
        baseline = self.requester.get(url, params=params)
        baseline_text = baseline.text.lower() if baseline else ""
        baseline_sigs = set(_match_signatures(baseline_text))
        baseline_len = len(baseline_text)

        for payload in SQLI_ERROR_PAYLOADS:
            test_params = {**params, param_name: str(params[param_name]) + payload}
            resp = self.requester.get(url, params=test_params)
            if resp is None:
                continue

            body = resp.text.lower()
            matched = set(_match_signatures(body)) - baseline_sigs
            if matched:
                sample = next(iter(matched))
                return Finding(
                    check_name=self.NAME,
                    title=f"SQL Injection via URL Parameter '{param_name}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Parameter '{param_name}' is injectable. SQL error signatures "
                        "were detected in the response after payload injection."
                    ),
                    evidence=f"Payload: {payload!r} → matched signature: '{sample}'",
                    remediation=(
                        "Use parameterised queries or prepared statements. "
                        "Never concatenate user input into SQL strings."
                    ),
                    url=url, cwe="CWE-89", owasp="A03:2021",
                )

            # Secondary signal: large response divergence without error string
            if baseline_len > 0:
                ratio = abs(len(body) - baseline_len) / baseline_len
                if ratio > 0.5 and resp.status_code != (baseline.status_code if baseline else 200):
                    return Finding(
                        check_name=self.NAME,
                        title=f"Potential SQL Injection via Parameter '{param_name}' (Unconfirmed)",
                        severity=Severity.LOW,
                        description=(
                            f"Parameter '{param_name}' produced a significantly different "
                            "response when injected with SQL payloads. Manual verification needed."
                        ),
                        evidence=(
                            f"Payload: {payload!r} → response size changed by {ratio*100:.0f}%, "
                            f"status: {resp.status_code}"
                        ),
                        remediation="Review SQL query construction for this parameter.",
                        url=url, cwe="CWE-89", owasp="A03:2021",
                    )

        return None

    def _test_form(self, form: dict) -> List[Finding]:
        findings = []
        testable = [
            f for f in form["fields"]
            if f.get("name") and f.get("type", "text") not in ("submit", "file", "button")
        ]
        if not testable:
            return findings

        # Build default form data
        default_data = {
            f["name"]: f.get("value") or "1"
            for f in form["fields"]
            if f.get("name") and f.get("type") != "file"
        }

        # Baseline submission
        method = form.get("method", "GET").upper()
        if method == "POST":
            baseline = self.requester.post(form["action"], data=default_data)
        else:
            baseline = self.requester.get(form["action"], params=default_data)

        baseline_text = baseline.text.lower() if baseline else ""
        baseline_sigs = set(_match_signatures(baseline_text))

        for field in testable:
            field_name = field["name"]
            for payload in SQLI_ERROR_PAYLOADS:
                data = {**default_data, field_name: str(default_data.get(field_name, "1")) + payload}
                if method == "POST":
                    resp = self.requester.post(form["action"], data=data)
                else:
                    resp = self.requester.get(form["action"], params=data)

                if resp is None:
                    continue

                body = resp.text.lower()
                matched = set(_match_signatures(body)) - baseline_sigs
                if matched:
                    sample = next(iter(matched))
                    findings.append(Finding(
                        check_name=self.NAME,
                        title=f"SQL Injection via Form Field '{field_name}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Form field '{field_name}' at {form['action']} is injectable."
                        ),
                        evidence=f"Payload: {payload!r} → matched: '{sample}'",
                        remediation=(
                            "Use parameterised queries or prepared statements."
                        ),
                        url=form["action"], cwe="CWE-89", owasp="A03:2021",
                    ))
                    break  # Confirmed for this field

        return findings
