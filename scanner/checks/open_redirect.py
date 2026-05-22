from __future__ import annotations

from typing import List
from urllib.parse import urlparse, urljoin

from scanner.core.models import Config, Finding, Severity
from scanner.core.requester import Requester
from scanner.utils.crawler import CrawlerData
from scanner.utils.payloads import OPEN_REDIRECT_PAYLOADS, REDIRECT_PARAMS

_EVIL_DOMAIN = "evil-attacker.com"


def _is_external_redirect(location: str) -> bool:
    """Return True if Location header points to our evil domain."""
    try:
        parsed = urlparse(location)
        netloc = parsed.netloc.lower().lstrip("/")
        return _EVIL_DOMAIN in netloc
    except Exception:
        return False


class OpenRedirectCheck:
    NAME = "Open Redirect"

    def __init__(self, requester: Requester, config: Config):
        self.requester = requester
        self.config = config

    def run(self, crawler_data: CrawlerData) -> List[Finding]:
        findings: List[Finding] = []

        # Test query params discovered via crawl
        for entry in crawler_data.query_params:
            url = entry["url"]
            params = entry["params"]
            for param_name in params:
                if param_name.lower() in REDIRECT_PARAMS:
                    f = self._test_param(url, dict(params), param_name, crawler_data.base_url)
                    findings.extend(f)

        # Brute-force common redirect params on the base URL even if not crawled
        for param in REDIRECT_PARAMS:
            for payload in OPEN_REDIRECT_PAYLOADS:
                resp = self.requester.get(
                    crawler_data.base_url,
                    params={param: payload},
                    allow_redirects=False,
                )
                if resp is None:
                    continue
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if _is_external_redirect(location):
                        findings.append(Finding(
                            check_name=self.NAME,
                            title=f"Open Redirect via Parameter '{param}'",
                            severity=Severity.HIGH,
                            description=(
                                f"The '{param}' parameter can redirect users to an external "
                                "attacker-controlled domain. This is commonly used in phishing."
                            ),
                            evidence=f"GET ?{param}={payload} → {resp.status_code} Location: {location}",
                            remediation=(
                                "Validate redirect destinations against an allowlist of trusted URLs. "
                                "Avoid using user-supplied values directly in Location headers."
                            ),
                            url=crawler_data.base_url,
                            cwe="CWE-601",
                            owasp="A01:2021",
                        ))
                        break  # One payload confirmed this param — move to next

        return findings

    def _test_param(
        self, url: str, params: dict, param_name: str, base_url: str
    ) -> List[Finding]:
        findings = []
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_params = {**params, param_name: payload}
            resp = self.requester.get(url, params=test_params, allow_redirects=False)
            if resp is None:
                continue
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if _is_external_redirect(location):
                    findings.append(Finding(
                        check_name=self.NAME,
                        title=f"Open Redirect via Parameter '{param_name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"The '{param_name}' parameter redirects to an external domain."
                        ),
                        evidence=f"GET {url}?{param_name}={payload} → {resp.status_code} Location: {location}",
                        remediation=(
                            "Validate redirect destinations against a trusted allowlist."
                        ),
                        url=url, cwe="CWE-601", owasp="A01:2021",
                    ))
                    break
        return findings
