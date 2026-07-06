"""
Abstract base reporter class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from ..models.scan_result import ScanResult


class BaseReporter(ABC):

    def __init__(self, output_dir: str = ".") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        """
        Generate a report from the scan result.
        Returns the path to the generated file.
        """
        ...

    def _make_path(self, result: ScanResult, extension: str, filename: Optional[str] = None) -> Path:
        if filename:
            return self.output_dir / filename
        safe_target = result.target_url.replace("://", "_").replace("/", "_").strip("_")[:40]
        return self.output_dir / f"webshield_{result.scan_id}_{safe_target}.{extension}"
