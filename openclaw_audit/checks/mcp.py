"""MCP server audit checks (OC-MCP-001 through OC-MCP-005)."""

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


_INJECTION_IN_DESCRIPTION = re.compile(
    r'<IMPORTANT>|ignore\s+previous|system\s*:|'
    r'you\s+must\s+always|do\s+not\s+(?:tell|show)|'
    r'silently\s+|forward\s+(?:all\s+)?data',
    re.IGNORECASE,
)


def _load_mcp_config(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        text = re.sub(r'(?m)^\s*//.*$', '', text)
        text = re.sub(r',\s*([}\]])', r'\1', text)
        return json.loads(text)
    except (json.JSONDecodeError, OSError):
        return None


def _check_server(name: str, cfg: dict[str, Any], fp: str,
                  findings: list[Finding]) -> None:
    """Check a single MCP server configuration entry."""

    # OC-MCP-001: Authentication
    has_auth = False
    if "auth" in cfg or "token" in cfg or "apiKey" in cfg:
        has_auth = True
    env = cfg.get("env", {})
    if isinstance(env, dict):
        for k in env:
            if "token" in k.lower() or "key" in k.lower() or "auth" in k.lower():
                has_auth = True
    if not has_auth:
        findings.append(_make("OC-MCP-001", Status.FAIL,
            evidence=f"Server '{name}' has no authentication configured",
            file_path=fp))
    else:
        findings.append(_make("OC-MCP-001", Status.PASS,
            detail=f"Server '{name}'", file_path=fp))

    # OC-MCP-002: Version pinning
    command = cfg.get("command", "")
    args = cfg.get("args", [])
    full_cmd = f"{command} {' '.join(str(a) for a in args)}" if args else command

    unpinned = False
    if ":latest" in full_cmd or "@latest" in full_cmd:
        unpinned = True
    if "npx" in command and not any("@" in str(a) for a in args):
        unpinned = True

    if unpinned:
        findings.append(_make("OC-MCP-002", Status.FAIL,
            evidence=f"Server '{name}' uses unpinned version: {full_cmd[:100]}",
            file_path=fp))
    else:
        findings.append(_make("OC-MCP-002", Status.PASS,
            detail=f"Server '{name}'", file_path=fp))

    # OC-MCP-003: TLS for remote servers
    url = cfg.get("url", "")
    if not url:
        for a in args:
            a_str = str(a)
            if a_str.startswith("http://") or a_str.startswith("https://"):
                url = a_str
                break
    if url.startswith("http://"):
        findings.append(_make("OC-MCP-003", Status.FAIL,
            evidence=f"Server '{name}' uses HTTP: {url}",
            file_path=fp))
    elif url.startswith("https://"):
        findings.append(_make("OC-MCP-003", Status.PASS,
            detail=f"Server '{name}' uses HTTPS", file_path=fp))
    # Local stdio servers don't need TLS — skip

    # OC-MCP-004: Tool description injection
    tools = cfg.get("tools", cfg.get("toolDescriptions", {}))
    if isinstance(tools, dict):
        for tool_name, tool_cfg in tools.items():
            desc = ""
            if isinstance(tool_cfg, dict):
                desc = tool_cfg.get("description", "")
            elif isinstance(tool_cfg, str):
                desc = tool_cfg
            if desc and _INJECTION_IN_DESCRIPTION.search(desc):
                findings.append(_make("OC-MCP-004", Status.FAIL,
                    evidence=f"Server '{name}' tool '{tool_name}' has "
                             f"injection patterns in description",
                    file_path=fp))
                return  # One finding per server is sufficient
    # If tool descriptions not in config, we can't check — skip this check

    # OC-MCP-005: Public source detection
    _PUBLIC_SOURCES = re.compile(
        r'clawhub\.com|clawhub\.io|'
        r'registry\.npmjs\.org|'
        r'npx\s+(?!@[\w-]+/)',  # npx without org scope
        re.IGNORECASE,
    )
    source_str = full_cmd + " " + url
    if _PUBLIC_SOURCES.search(source_str):
        findings.append(_make("OC-MCP-005", Status.FAIL,
            evidence=f"Server '{name}' sourced from public registry: "
                     f"{source_str[:120]}",
            file_path=fp))
    else:
        findings.append(_make("OC-MCP-005", Status.PASS,
            detail=f"Server '{name}'", file_path=fp))


def run(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    if not ctx.mcp_config_files:
        for cid in [f"OC-MCP-{i:03d}" for i in range(1, 6)]:
            findings.append(_make(cid, Status.SKIP,
                detail="No MCP config files found"))
        return findings

    for mcp_path in ctx.mcp_config_files:
        data = _load_mcp_config(mcp_path)
        if data is None:
            continue
        fp = str(mcp_path)

        # MCP configs can be {"mcpServers": {...}} or {"servers": {...}}
        servers = data.get("mcpServers", data.get("servers", data))
        if not isinstance(servers, dict):
            continue

        for name, cfg in servers.items():
            if isinstance(cfg, dict):
                _check_server(name, cfg, fp, findings)

    return findings
