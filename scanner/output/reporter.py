from __future__ import annotations

import json

from scanner.core.models import ScanResult


class JSONReporter:
    def write(self, result: ScanResult, filepath: str) -> None:
        data = result.to_dict()
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
