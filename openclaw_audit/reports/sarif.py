"""SARIF 2.1.0 output reporter for CI/CD integration."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding, ScanReport, Severity, Status


_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _finding_to_result(f: Finding) -> dict:
    """Convert a Finding to a SARIF result object."""
    result: dict = {
        "ruleId": f.check_id,
        "level": _SEVERITY_MAP.get(f.severity, "warning") if f.status == Status.FAIL else "none",
        "message": {
            "text": f.description,
        },
        "properties": {
            "status": f.status.value,
            "severity": f.severity.value,
            "category": f.category,
        },
    }

    if f.evidence:
        result["message"]["text"] += f"\n\nEvidence: {f.evidence}"
    if f.recommendation:
        result["properties"]["recommendation"] = f.recommendation

    if f.frameworks:
        result["properties"]["frameworks"] = f.frameworks.to_dict()

    if f.file_path:
        result["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f.file_path,
                },
            },
        }]

    return result


def render(report: ScanReport, output_path: Path | None = None) -> str:
    """Render report as SARIF 2.1.0."""
    from ..mappings import CHECKS

    # Build rules from check definitions
    rules = []
    seen_rules = set()
    for f in report.findings:
        if f.check_id not in seen_rules:
            seen_rules.add(f.check_id)
            check = CHECKS.get(f.check_id)
            rule: dict = {
                "id": f.check_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {
                    "level": _SEVERITY_MAP.get(f.severity, "warning"),
                },
                "properties": {
                    "category": f.category,
                    "severity": f.severity.value,
                },
            }
            if check and check.recommendation:
                rule["help"] = {"text": check.recommendation}
            rules.append(rule)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "openclaw-audit",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/cloudsecurityalliance/openclaw-audit",
                    "rules": rules,
                },
            },
            "results": [_finding_to_result(f) for f in report.findings],
            "invocations": [{
                "executionSuccessful": True,
                "properties": {
                    "target": report.target,
                    "contextType": report.context_type,
                    "scanMode": report.scan_mode,
                },
            }],
        }],
    }

    text = json.dumps(sarif, indent=2, default=str)
    if output_path:
        output_path.write_text(text, encoding="utf-8")
    return text
