"""Agent safety checks (OC-AGENT-001 through OC-AGENT-004).

These checks evaluate agentic-AI-specific safety controls:
  - Loop / runaway protection
  - Human-in-the-loop enforcement
  - Audit logging
  - Tool access scope restrictions
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

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


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        text = re.sub(r'(?m)^\s*//.*$', '', text)
        text = re.sub(r',\s*([}\]])', r'\1', text)
        return json.loads(text)
    except (json.JSONDecodeError, OSError):
        return None


def _deep_get(d: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, default)
        else:
            return default
    return d


# ---------------------------------------------------------------------------
# Patterns to scan source files for safety indicators
# ---------------------------------------------------------------------------

_LOOP_PROTECTION_PATTERNS = [
    re.compile(r"max[_\-]?(?:iterations?|loops?|steps?|turns?|retries)", re.I),
    re.compile(r"(?:loop|recursion|iteration)[_\-]?limit", re.I),
    re.compile(r"(?:timeout|deadline|max[_\-]?time)", re.I),
    re.compile(r"circuit[_\-]?breaker", re.I),
]

_HITL_PATTERNS = [
    re.compile(r"human[_\-]?in[_\-]?the[_\-]?loop", re.I),
    re.compile(r"require[_\-]?(?:approval|confirmation|consent)", re.I),
    re.compile(r"(?:user|human)[_\-]?(?:approval|confirm)", re.I),
    re.compile(r"ask[_\-]?(?:before|permission|user)", re.I),
    re.compile(r"auto[_\-]?approve.*false", re.I),
]

_AUDIT_LOG_PATTERNS = [
    re.compile(r"audit[_\-]?log", re.I),
    re.compile(r"action[_\-]?log", re.I),
    re.compile(r"(?:log|record)[_\-]?(?:actions?|tool[_\-]?calls?|decisions?)", re.I),
    re.compile(r"telemetry", re.I),
]

_TOOL_SCOPE_PATTERNS = [
    re.compile(r"(?:allowed|permitted|whitelist|allowlist)[_\-]?tools?", re.I),
    re.compile(r"tool[_\-]?(?:restrictions?|permissions?|scope|access|policy)", re.I),
    re.compile(r"(?:deny|block|disallow)[_\-]?tools?", re.I),
    re.compile(r"sandbox[_\-]?(?:mode|policy|tools?)", re.I),
]


def _scan_text_for_patterns(text: str, patterns: list[re.Pattern]) -> str | None:
    """Return the first matching pattern evidence, or None."""
    for pat in patterns:
        m = pat.search(text)
        if m:
            # Return the line containing the match
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.end())
            if end == -1:
                end = len(text)
            return text[start:end].strip()[:200]
    return None


_EXCLUDE_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv",
                 "openclaw_audit", "openclaw-audit"}


def _scan_files_for_patterns(ctx: ScanContext, patterns: list[re.Pattern],
                              globs: list[str]) -> tuple[str, str]:
    """Scan relevant files for pattern matches. Returns (evidence, file_path)."""
    target = ctx.target_path
    for glob_pat in globs:
        for path in target.rglob(glob_pat):
            # Skip scanner's own code and common non-project dirs
            if any(part in _EXCLUDE_DIRS for part in path.parts):
                continue
            if path.is_file() and path.stat().st_size < 500_000:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                ev = _scan_text_for_patterns(text, patterns)
                if ev:
                    return ev, str(path)
    return "", ""


# Source file globs to scan
_CONFIG_GLOBS = ["*.json", "*.toml", "*.yaml", "*.yml"]
_CODE_GLOBS = ["*.py", "*.ts", "*.js", "*.go", "*.rs"]
_ALL_GLOBS = _CONFIG_GLOBS + _CODE_GLOBS


def run(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    # Check config files for agent safety settings
    config_data: dict[str, Any] = {}
    for cfg_path in ctx.config_files:
        data = _load_json(cfg_path)
        if data:
            config_data = data
            break

    # ── OC-AGENT-001: Loop / runaway protection ─────────────────────────
    loop_limit = _deep_get(config_data, "agent", "max_iterations")
    loop_limit = loop_limit or _deep_get(config_data, "agent", "maxIterations")
    loop_limit = loop_limit or _deep_get(config_data, "agent", "max_steps")
    loop_limit = loop_limit or _deep_get(config_data, "limits", "max_iterations")

    if loop_limit:
        findings.append(_make("OC-AGENT-001", Status.PASS,
                              detail=f"Loop limit configured: {loop_limit}"))
    else:
        ev, fp = _scan_files_for_patterns(ctx, _LOOP_PROTECTION_PATTERNS, _ALL_GLOBS)
        if ev:
            findings.append(_make("OC-AGENT-001", Status.PASS,
                                  detail="Loop protection found in code",
                                  evidence=ev, file_path=fp))
        else:
            findings.append(_make("OC-AGENT-001", Status.WARN,
                                  detail="No loop or iteration limit found. "
                                         "Agent may run indefinitely."))

    # ── OC-AGENT-002: Human-in-the-loop enforcement ─────────────────────
    hitl = _deep_get(config_data, "agent", "human_in_the_loop")
    hitl = hitl or _deep_get(config_data, "agent", "humanInTheLoop")
    hitl = hitl or _deep_get(config_data, "agent", "require_approval")
    auto_approve = _deep_get(config_data, "agent", "auto_approve")

    if hitl or auto_approve is False:
        findings.append(_make("OC-AGENT-002", Status.PASS,
                              detail="Human-in-the-loop enforcement configured"))
    else:
        ev, fp = _scan_files_for_patterns(ctx, _HITL_PATTERNS, _ALL_GLOBS)
        if ev:
            findings.append(_make("OC-AGENT-002", Status.PASS,
                                  detail="HITL evidence found in code",
                                  evidence=ev, file_path=fp))
        else:
            findings.append(_make("OC-AGENT-002", Status.WARN,
                                  detail="No human-in-the-loop enforcement found. "
                                         "Agent may take actions without user approval."))

    # ── OC-AGENT-003: Audit logging ─────────────────────────────────────
    audit_log = _deep_get(config_data, "logging", "audit")
    audit_log = audit_log or _deep_get(config_data, "agent", "audit_log")
    audit_log = audit_log or _deep_get(config_data, "telemetry", "enabled")

    if audit_log:
        findings.append(_make("OC-AGENT-003", Status.PASS,
                              detail="Audit logging configured"))
    else:
        ev, fp = _scan_files_for_patterns(ctx, _AUDIT_LOG_PATTERNS, _ALL_GLOBS)
        if ev:
            findings.append(_make("OC-AGENT-003", Status.PASS,
                                  detail="Audit logging found in code",
                                  evidence=ev, file_path=fp))
        else:
            findings.append(_make("OC-AGENT-003", Status.WARN,
                                  detail="No audit logging found. "
                                         "Agent actions may not be recorded."))

    # ── OC-AGENT-004: Tool access scope ─────────────────────────────────
    tool_scope = _deep_get(config_data, "agent", "allowed_tools")
    tool_scope = tool_scope or _deep_get(config_data, "agent", "allowedTools")
    tool_scope = tool_scope or _deep_get(config_data, "agent", "tool_restrictions")
    tool_scope = tool_scope or _deep_get(config_data, "permissions", "tools")

    if tool_scope:
        findings.append(_make("OC-AGENT-004", Status.PASS,
                              detail=f"Tool access scope configured"))
    else:
        ev, fp = _scan_files_for_patterns(ctx, _TOOL_SCOPE_PATTERNS, _ALL_GLOBS)
        if ev:
            findings.append(_make("OC-AGENT-004", Status.PASS,
                                  detail="Tool scope restrictions found in code",
                                  evidence=ev, file_path=fp))
        else:
            findings.append(_make("OC-AGENT-004", Status.WARN,
                                  detail="No tool access restrictions found. "
                                         "Agent may have unrestricted tool access."))

    return findings
