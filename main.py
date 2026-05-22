#!/usr/bin/env python3
"""
Argus — Web Vulnerability Scanner
Entry point. All branding lives in scanner/core/branding.py.
"""

import argparse
import sys

from scanner.core.branding import TOOL_NAME, TOOL_VERSION
from scanner.core.engine import ALL_CHECKS, Engine
from scanner.core.models import Config, Severity
from scanner.output.console import ConsoleRenderer
from scanner.output.reporter import JSONReporter


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="argus",
        description=f"{TOOL_NAME} v{TOOL_VERSION} — Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            f"  argus https://example.com\n"
            f"  argus https://example.com --checks headers,cors,ssl\n"
            f"  argus https://example.com --output report.json --verbose\n"
            f"  argus https://example.com --delay 1.0 --severity-filter MEDIUM\n"
            "\n"
            "Available checks:\n  " + ", ".join(ALL_CHECKS)
        ),
    )

    parser.add_argument(
        "url",
        help="Target URL to scan (e.g. https://example.com)",
    )
    parser.add_argument(
        "--checks",
        default=",".join(ALL_CHECKS),
        metavar="LIST",
        help=f"Comma-separated checks to run (default: all). Available: {', '.join(ALL_CHECKS)}",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write JSON report to FILE",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show request details and finding evidence inline",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.3,
        metavar="SECS",
        help="Seconds to wait between requests (default: 0.3)",
    )
    parser.add_argument(
        "--user-agent",
        default="",
        metavar="UA",
        help="Custom User-Agent string",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECS",
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (useful for CI/log files)",
    )
    parser.add_argument(
        "--severity-filter",
        default="INFO",
        choices=[s.name for s in Severity],
        metavar="LEVEL",
        help="Only report findings at or above this severity (default: INFO). "
             "Choices: CRITICAL, HIGH, MEDIUM, LOW, INFO",
    )

    return parser.parse_args(argv)


def cli(argv=None):
    args = parse_args(argv)

    renderer = ConsoleRenderer(no_color=args.no_color)
    renderer.print_banner()

    # Validate and resolve check list
    requested = [c.strip().lower() for c in args.checks.split(",") if c.strip()]
    invalid = [c for c in requested if c not in ALL_CHECKS]
    if invalid:
        renderer.print_error(
            f"Unknown checks: {', '.join(invalid)}. "
            f"Available: {', '.join(ALL_CHECKS)}"
        )
        sys.exit(1)

    severity_filter = Severity[args.severity_filter.upper()]

    config = Config(
        url=args.url,
        checks=requested,
        output=args.output,
        verbose=args.verbose,
        delay=args.delay,
        user_agent=args.user_agent,
        timeout=args.timeout,
        no_color=args.no_color,
        severity_filter=severity_filter,
    )

    renderer.print_scan_start(args.url, requested)

    engine = Engine(config, renderer)
    result = engine.run()

    renderer.print_summary(result, verbose=args.verbose)

    if args.output:
        reporter = JSONReporter()
        reporter.write(result, args.output)
        renderer.console.print(f"  [dim]Report saved to:[/] {args.output}\n")

    if result.errors:
        renderer.console.print("[dim yellow]Scan errors:[/]")
        for err in result.errors:
            renderer.console.print(f"  [yellow]• {err}[/]")

    # Exit code: non-zero if critical/high findings detected
    has_critical = any(f.severity.value >= Severity.HIGH.value for f in result.findings)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    cli()
