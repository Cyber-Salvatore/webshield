"""
JSON Report Generator
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .base_reporter import BaseReporter
from ..models.scan_result import ScanResult


class JSONReporter(BaseReporter):

    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        output_path = self._make_path(result, "json", filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report_data = result.to_dict()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
        return str(output_path)
