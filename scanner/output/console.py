from __future__ import annotations

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from scanner.core.branding import (
    ASCII_ART, TOOL_COLOR, TOOL_LEGAL, TOOL_NAME, TOOL_TAGLINE, TOOL_VERSION,
)
from scanner.core.models import Finding, ScanResult, Severity


class ConsoleRenderer:
    def __init__(self, no_color: bool = False):
        self.console = Console(highlight=False, markup=True, no_color=no_color)

    def print_banner(self):
        self.console.print(f"[{TOOL_COLOR}]{ASCII_ART}[/]")
        self.console.print(
            f"  [{TOOL_COLOR}]{TOOL_TAGLINE}[/]  [dim]•[/]  "
            f"[dim]v{TOOL_VERSION}[/]"
        )
        self.console.print(f"  [dim]{TOOL_LEGAL}[/]\n")

    def print_scan_start(self, url: str, checks: List[str]):
        self.console.print(f"[bold]Target:[/] [underline]{url}[/]")
        self.console.print(f"[bold]Checks:[/] {', '.join(checks)}\n")

    def print_check_start(self, check_name: str):
        self.console.print(f"[dim]  Running {check_name}...[/]")

    def print_finding(self, finding: Finding, verbose: bool = False):
        color = finding.severity.color()
        self.console.print(
            f"  [{color}][{finding.severity.name}][/] "
            f"[bold]{finding.title}[/]"
        )
        if verbose:
            self.console.print(f"    [dim]Evidence:[/] {finding.evidence}")
            self.console.print(f"    [dim]Fix:[/]      {finding.remediation}")

    def print_summary(self, result: ScanResult, verbose: bool = False):
        self.console.print()

        if not result.findings:
            self.console.print(
                Panel("[green]No findings detected.[/]", title="Scan Complete", border_style="green")
            )
            return

        table = Table(
            title=f"Findings for {result.target}",
            box=box.ROUNDED,
            show_lines=False,
        )
        table.add_column("Sev", style="bold", width=10)
        table.add_column("Check", style="dim", width=20)
        table.add_column("Title", width=50)
        table.add_column("URL", style="dim", width=40)

        sorted_findings = sorted(
            result.findings, key=lambda f: f.severity.value, reverse=True
        )
        for f in sorted_findings:
            color = f.severity.color()
            table.add_row(
                f"[{color}]{f.severity.name}[/]",
                f.check_name,
                f.title,
                f.url,
            )

        self.console.print(table)

        # Severity count summary
        counts = {s.name: 0 for s in Severity}
        for f in result.findings:
            counts[f.severity.name] += 1

        summary_parts = []
        for sev in reversed(list(Severity)):
            if counts[sev.name]:
                color = sev.color()
                summary_parts.append(f"[{color}]{sev.name}: {counts[sev.name]}[/]")

        self.console.print(
            f"\n  Total: [bold]{len(result.findings)}[/] findings  •  "
            + "  ".join(summary_parts)
        )
        self.console.print(
            f"  Duration: [dim]{result.duration_seconds:.1f}s[/]\n"
        )

    def print_error(self, message: str):
        self.console.print(f"[bold red]Error:[/] {message}")

    def verbose(self, message: str):
        self.console.print(message)
