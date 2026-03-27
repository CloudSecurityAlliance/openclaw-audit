"""JSON output reporter."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import ScanReport


def render(report: ScanReport, output_path: Path | None = None) -> str:
    """Render report as JSON. Write to file if path given, else return string."""
    data = report.to_dict()
    text = json.dumps(data, indent=2, default=str)
    if output_path:
        output_path.write_text(text, encoding="utf-8")
    return text
