from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    def label(self) -> str:
        return self.name

    def color(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim white",
        }[self.name]


@dataclass
class Finding:
    check_name: str
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    url: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "check": self.check_name,
            "title": self.title,
            "severity": self.severity.name,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "owasp": self.owasp,
        }


@dataclass
class ScanResult:
    target: str
    scan_time: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0

    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        grouped: Dict[str, List[Finding]] = {s.name: [] for s in Severity}
        for f in self.findings:
            grouped[f.severity.name].append(f)
        return grouped

    def to_dict(self) -> dict:
        summary = {s.name: 0 for s in Severity}
        for f in self.findings:
            summary[f.severity.name] += 1
        return {
            "meta": {
                "tool": self.metadata.get("tool", ""),
                "version": self.metadata.get("version", ""),
                "target": self.target,
                "scan_time": self.scan_time,
                "duration_seconds": round(self.duration_seconds, 2),
                "checks_run": self.metadata.get("checks_run", []),
                "total_findings": len(self.findings),
            },
            "summary": summary,
            "findings": [
                {"id": f"FIND-{i+1:03d}", **f.to_dict()}
                for i, f in enumerate(
                    sorted(self.findings, key=lambda x: x.severity.value, reverse=True)
                )
            ],
            "errors": self.errors,
        }


@dataclass
class Config:
    url: str
    checks: List[str]
    output: Optional[str]
    verbose: bool
    delay: float
    user_agent: str
    timeout: int
    no_color: bool
    severity_filter: Severity
