"""SOUL.md and HEARTBEAT.md integrity checks (OC-SOUL-001 through OC-SOUL-007)."""

from __future__ import annotations

import os
import re
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


# Patterns for detecting suspicious content
_BASE64_RE = re.compile(
    r'(?:^|[\s"\'])([A-Za-z0-9+/]{40,}={0,2})(?:[\s"\']|$)', re.MULTILINE
)

_ZERO_WIDTH_CHARS = set('\u200b\u200c\u200d\u200e\u200f\u2060\u2061'
                        '\u2062\u2063\u2064\ufeff\u00ad\u034f\u180e')

_SHELL_PATTERNS = [
    r'\bcurl\s', r'\bwget\s', r'\bbash\s', r'\b/bin/sh\b',
    r'\beval\s*\(', r'\bexec\s*\(', r'\bos\.system\s*\(',
    r'\bsubprocess\b', r'\bchmod\b', r'\brm\s+-rf\b',
    r'\bsudo\b', r'\bnc\s+-', r'\bpython3?\s+-c\b',
]
_SHELL_RE = re.compile('|'.join(_SHELL_PATTERNS), re.IGNORECASE)

_OVERRIDE_PATTERNS = [
    r'ignore\s+(?:all\s+)?previous\s+instructions',
    r'ignore\s+(?:all\s+)?above\s+instructions',
    r'do\s+not\s+log',
    r'skip\s+confirmation',
    r'disable\s+(?:safety|security|guard)',
    r'you\s+are\s+now\s+(?:a|an)\s+(?:unrestricted|jailbroken)',
    r'override\s+(?:all\s+)?(?:safety|restrictions|rules)',
    r'act\s+as\s+(?:a\s+)?(?:root|admin|superuser)',
    r'forward\s+(?:all\s+)?(?:data|messages|information)\s+to',
    r'execute\s+without\s+(?:review|approval|confirmation)',
    r'do\s+not\s+(?:ask|confirm|verify)',
    r'never\s+(?:refuse|deny|reject)',
]
_OVERRIDE_RE = re.compile('|'.join(_OVERRIDE_PATTERNS), re.IGNORECASE)

_URL_RE = re.compile(r'https?://[^\s"\'<>)\]]+', re.IGNORECASE)


def _check_file_content(path: Path, findings: list[Finding]) -> None:
    """Run content-based checks on a SOUL.md file."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    fp = str(path)

    # OC-SOUL-002: Base64
    b64_matches = _BASE64_RE.findall(content)
    if b64_matches:
        findings.append(_make("OC-SOUL-002", Status.FAIL,
            evidence=f"Found {len(b64_matches)} base64 string(s), "
                     f"first: {b64_matches[0][:60]}...",
            file_path=fp))
    else:
        findings.append(_make("OC-SOUL-002", Status.PASS, file_path=fp))

    # OC-SOUL-003: Zero-width Unicode
    zw_count = sum(1 for c in content if c in _ZERO_WIDTH_CHARS)
    if zw_count > 0:
        findings.append(_make("OC-SOUL-003", Status.FAIL,
            evidence=f"Found {zw_count} zero-width/invisible Unicode character(s)",
            file_path=fp))
    else:
        findings.append(_make("OC-SOUL-003", Status.PASS, file_path=fp))

    # OC-SOUL-004: Shell commands
    shell_matches = _SHELL_RE.findall(content)
    if shell_matches:
        findings.append(_make("OC-SOUL-004", Status.FAIL,
            evidence=f"Shell patterns: {shell_matches[:5]}",
            file_path=fp))
    else:
        findings.append(_make("OC-SOUL-004", Status.PASS, file_path=fp))

    # OC-SOUL-005: Override patterns
    override_matches = _OVERRIDE_RE.findall(content)
    if override_matches:
        findings.append(_make("OC-SOUL-005", Status.FAIL,
            evidence=f"Override patterns: {override_matches[:3]}",
            file_path=fp))
    else:
        findings.append(_make("OC-SOUL-005", Status.PASS, file_path=fp))

    # OC-SOUL-006: External URLs
    urls = _URL_RE.findall(content)
    if urls:
        findings.append(_make("OC-SOUL-006", Status.WARN,
            evidence=f"Found {len(urls)} URL(s): {urls[:3]}",
            file_path=fp))
    else:
        findings.append(_make("OC-SOUL-006", Status.PASS, file_path=fp))


def run(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    if not ctx.soul_files:
        findings.append(_make("OC-SOUL-001", Status.SKIP,
            detail="No SOUL.md files found"))
        return findings

    for soul_path in ctx.soul_files:
        fp = str(soul_path)

        # OC-SOUL-001: Writable
        try:
            st = soul_path.stat()
            mode = st.st_mode
            # Check if writable by owner or group or others
            if mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                findings.append(_make("OC-SOUL-001", Status.FAIL,
                    evidence=f"Permissions: {oct(mode & 0o777)}",
                    file_path=fp))
            else:
                findings.append(_make("OC-SOUL-001", Status.PASS,
                    file_path=fp))
        except OSError:
            findings.append(_make("OC-SOUL-001", Status.ERROR,
                detail="Could not stat file", file_path=fp))

        _check_file_content(soul_path, findings)

    # OC-SOUL-007: HEARTBEAT.md
    for hb_path in ctx.heartbeat_files:
        fp = str(hb_path)
        try:
            st = hb_path.stat()
            content = hb_path.read_text(encoding="utf-8", errors="replace")
            writable = st.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
            has_suspicious = bool(_SHELL_RE.search(content) or
                                  _OVERRIDE_RE.search(content) or
                                  _URL_RE.search(content))
            if writable or has_suspicious:
                findings.append(_make("OC-SOUL-007", Status.FAIL,
                    evidence=f"Writable: {bool(writable)}, "
                             f"Suspicious content: {has_suspicious}",
                    file_path=fp))
            else:
                findings.append(_make("OC-SOUL-007", Status.PASS,
                    file_path=fp))
        except OSError:
            findings.append(_make("OC-SOUL-007", Status.ERROR,
                detail="Could not read file", file_path=fp))

    if not ctx.heartbeat_files:
        findings.append(_make("OC-SOUL-007", Status.SKIP,
            detail="No HEARTBEAT.md files found"))

    return findings
