from __future__ import annotations

import datetime
import time
from typing import List, Type
from urllib.parse import urlparse

from scanner.checks.cookies import CookiesCheck
from scanner.checks.cors import CORSCheck
from scanner.checks.headers import HeadersCheck
from scanner.checks.open_redirect import OpenRedirectCheck
from scanner.checks.sqli import SQLiCheck
from scanner.checks.ssl_tls import SSLCheck
from scanner.checks.traversal import TraversalCheck
from scanner.checks.xss import XSSCheck
from scanner.core.branding import TOOL_NAME, TOOL_VERSION
from scanner.core.models import Config, Finding, ScanResult
from scanner.core.requester import Requester
from scanner.output.console import ConsoleRenderer
from scanner.utils.crawler import Crawler, CrawlerData


CHECK_REGISTRY = {
    "headers": HeadersCheck,
    "ssl": SSLCheck,
    "cookies": CookiesCheck,
    "cors": CORSCheck,
    "open_redirect": OpenRedirectCheck,
    "traversal": TraversalCheck,
    "xss": XSSCheck,
    "sqli": SQLiCheck,
}

ALL_CHECKS = list(CHECK_REGISTRY.keys())


class Engine:
    def __init__(self, config: Config, renderer: ConsoleRenderer):
        self.config = config
        self.renderer = renderer
        self.requester = Requester(
            config,
            verbose_print=renderer.verbose if config.verbose else None,
        )

    def run(self) -> ScanResult:
        url = self._normalise_url(self.config.url)
        scan_time = datetime.datetime.utcnow().isoformat() + "Z"
        start = time.monotonic()

        result = ScanResult(
            target=url,
            scan_time=scan_time,
            metadata={
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
                "checks_run": self.config.checks,
            },
        )

        # Confirm target is reachable
        self.renderer.console.print(f"[dim]Checking target reachability...[/]")
        probe = self.requester.get(url)
        if probe is None:
            result.errors.append(f"Target unreachable: {url}")
            self.renderer.print_error(f"Target unreachable: {url}")
            result.duration_seconds = time.monotonic() - start
            return result

        self.renderer.console.print(
            f"[green]Target responded[/] [dim](HTTP {probe.status_code})[/]\n"
        )

        # Crawl the target page
        crawler = Crawler(self.requester)
        crawler_data = crawler.collect(url)

        # Run selected checks
        for check_name in self.config.checks:
            check_cls = CHECK_REGISTRY.get(check_name)
            if check_cls is None:
                result.errors.append(f"Unknown check: {check_name}")
                continue

            self.renderer.print_check_start(check_cls.NAME)
            try:
                check = check_cls(self.requester, self.config)
                findings = check.run(crawler_data)
                # Filter by severity
                filtered = [
                    f for f in findings
                    if f.severity.value >= self.config.severity_filter.value
                ]
                result.findings.extend(filtered)
                # Print findings as they are found
                for finding in filtered:
                    self.renderer.print_finding(finding, self.config.verbose)
            except Exception as exc:
                msg = f"Check '{check_name}' failed: {exc}"
                result.errors.append(msg)
                if self.config.verbose:
                    self.renderer.print_error(msg)

        result.duration_seconds = time.monotonic() - start
        return result

    @staticmethod
    def _normalise_url(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")
