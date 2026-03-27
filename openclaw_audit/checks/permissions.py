"""File permission checks (OC-PERM-001, OC-PERM-002)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ..models import Finding, ScanContext, Severity, Status
from ..mappings import CHECKS


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


def run(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    # OC-PERM-001: Config directory permissions
    target = ctx.target_path
    try:
        st = target.stat()
        mode = st.st_mode & 0o777
        if mode & 0o077:  # group or other has any access
            findings.append(_make("OC-PERM-001", Status.FAIL,
                evidence=f"Permissions: {oct(mode)} (expected 700 or tighter)",
                file_path=str(target)))
        else:
            findings.append(_make("OC-PERM-001", Status.PASS,
                detail=f"Permissions: {oct(mode)}", file_path=str(target)))
    except OSError:
        findings.append(_make("OC-PERM-001", Status.ERROR,
            detail="Could not stat directory"))

    # OC-PERM-002: Credential/config file permissions
    sensitive_patterns = [
        "auth-profiles.json", "credentials.json", "*.key", "*.pem",
        "config.json", "config.json5",
    ]
    bad_files = []
    for pattern in sensitive_patterns:
        for f in target.rglob(pattern):
            if not f.is_file():
                continue
            try:
                fmode = f.stat().st_mode & 0o777
                if fmode & 0o077:  # group or other has access
                    bad_files.append((str(f), oct(fmode)))
            except OSError:
                pass

    if bad_files:
        evidence_lines = "; ".join(f"{p} ({m})" for p, m in bad_files[:5])
        if len(bad_files) > 5:
            evidence_lines += f"; ...and {len(bad_files) - 5} more"
        findings.append(_make("OC-PERM-002", Status.FAIL,
            evidence=evidence_lines))
    else:
        findings.append(_make("OC-PERM-002", Status.PASS))

    return findings
