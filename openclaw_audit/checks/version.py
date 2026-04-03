"""Version checks (OC-VER-001, OC-VER-002)."""

from __future__ import annotations

import re

from ..models import Finding, ScanContext, Severity, Status
from ..mappings import CHECKS

MINIMUM_SAFE_VERSION = "2026.3.12"


def _make(check_id: str, status: Status, detail: str = "",
          evidence: str = "", file_path: str = "") -> Finding:
    c = CHECKS[check_id]
    return Finding(
        check_id=check_id, status=status, title=c.title,
        severity=c.severity if status == Status.FAIL else Severity.INFO,
        category=c.category, description=c.description,
        detail=detail, evidence=evidence, file_path=file_path,
        recommendation=c.recommendation if status != Status.PASS else "",
        frameworks=c.frameworks, fix_level=c.fix_level,
    )


def _parse_version(v: str) -> tuple[int, ...] | None:
    """Parse version string into comparable tuple."""
    # Handle formats: "2026.2.26", "v2026.2.26", "0.5.0", "v0.5.0"
    v = v.strip().lstrip("v")
    parts = re.split(r'[.\-]', v)
    try:
        return tuple(int(p) for p in parts if p.isdigit())
    except ValueError:
        return None


def run(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    if not ctx.openclaw_version:
        findings.append(_make("OC-VER-002", Status.FAIL,
            detail="Could not determine OpenClaw version from package.json or CLI"))
        return findings

    findings.append(_make("OC-VER-002", Status.PASS,
        detail=f"Version detected: {ctx.openclaw_version}"))

    current = _parse_version(ctx.openclaw_version)
    minimum = _parse_version(MINIMUM_SAFE_VERSION)

    if current is None or minimum is None:
        findings.append(_make("OC-VER-001", Status.WARN,
            detail=f"Could not parse version: {ctx.openclaw_version}"))
    elif current < minimum:
        findings.append(_make("OC-VER-001", Status.FAIL,
            evidence=f"Version {ctx.openclaw_version} < {MINIMUM_SAFE_VERSION}"))
    else:
        findings.append(_make("OC-VER-001", Status.PASS,
            detail=f"Version {ctx.openclaw_version} >= {MINIMUM_SAFE_VERSION}"))

    return findings
