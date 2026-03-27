"""Configuration audit checks (OC-CFG-001 through OC-CFG-013)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..models import Finding, ScanContext, Severity, Status
from ..mappings import CHECKS


def _load_json_config(path: Path) -> dict[str, Any] | None:
    """Load a JSON/JSON5 config file, stripping comments."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        # Strip single-line comments (// ...) but not inside strings
        text = re.sub(r'(?m)^\s*//.*$', '', text)
        text = re.sub(r',\s*([}\]])', r'\1', text)  # trailing commas
        return json.loads(text)
    except (json.JSONDecodeError, OSError):
        return None


def _deep_get(d: dict, *keys: str, default: Any = None) -> Any:
    """Navigate nested dicts."""
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, default)
        else:
            return default
    return d


def _make_finding(check_id: str, status: Status, detail: str = "",
                  evidence: str = "", file_path: str = "") -> Finding:
    c = CHECKS[check_id]
    return Finding(
        check_id=check_id,
        status=status,
        title=c.title,
        severity=c.severity if status == Status.FAIL else Severity.INFO,
        category=c.category,
        description=c.description,
        detail=detail,
        evidence=evidence,
        file_path=file_path,
        recommendation=c.recommendation if status != Status.PASS else "",
        frameworks=c.frameworks,
        fix_level=c.fix_level,
    )


def run(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    if not ctx.config_files:
        # No config files found — everything is default (mostly insecure)
        for cid in [f"OC-CFG-{i:03d}" for i in range(1, 14)]:
            if cid in CHECKS:
                findings.append(_make_finding(
                    cid, Status.WARN,
                    detail="No config file found; using OpenClaw defaults.",
                ))
        return findings

    for cfg_path in ctx.config_files:
        data = _load_json_config(cfg_path)
        if data is None:
            continue
        fp = str(cfg_path)

        # OC-CFG-001: Gateway auth
        auth_mode = _deep_get(data, "gateway", "auth", "mode")
        if not auth_mode or auth_mode == "none":
            findings.append(_make_finding("OC-CFG-001", Status.FAIL,
                evidence=f"gateway.auth.mode = {auth_mode!r}", file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-001", Status.PASS,
                detail=f"Auth mode: {auth_mode}", file_path=fp))

        # OC-CFG-002: Gateway bind
        bind = _deep_get(data, "gateway", "bind")
        mode = _deep_get(data, "gateway", "mode")
        if bind and bind not in ("loopback", "127.0.0.1", "localhost"):
            findings.append(_make_finding("OC-CFG-002", Status.FAIL,
                evidence=f"gateway.bind = {bind!r}", file_path=fp))
        elif mode and mode not in ("local",):
            findings.append(_make_finding("OC-CFG-002", Status.WARN,
                detail=f"gateway.mode = {mode!r}", file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-002", Status.PASS, file_path=fp))

        # OC-CFG-003: mDNS
        mdns = _deep_get(data, "discovery", "mdns", "mode")
        if mdns and mdns == "off":
            findings.append(_make_finding("OC-CFG-003", Status.PASS, file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-003", Status.FAIL,
                evidence=f"discovery.mdns.mode = {mdns!r}" if mdns else "mDNS not disabled",
                file_path=fp))

        # OC-CFG-004: Shell exec security
        exec_sec = _deep_get(data, "tools", "exec", "security")
        if exec_sec == "deny":
            findings.append(_make_finding("OC-CFG-004", Status.PASS, file_path=fp))
        elif exec_sec == "full":
            findings.append(_make_finding("OC-CFG-004", Status.FAIL,
                evidence="tools.exec.security = 'full' (arbitrary shell execution)",
                file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-004", Status.FAIL,
                evidence=f"tools.exec.security = {exec_sec!r}", file_path=fp))

        # OC-CFG-005: Tool approval
        exec_ask = _deep_get(data, "tools", "exec", "ask")
        if exec_ask == "always":
            findings.append(_make_finding("OC-CFG-005", Status.PASS, file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-005", Status.FAIL,
                evidence=f"tools.exec.ask = {exec_ask!r}", file_path=fp))

        # OC-CFG-006: Dangerous tool groups
        deny_list = _deep_get(data, "tools", "deny", default=[])
        if not isinstance(deny_list, list):
            deny_list = []
        dangerous = {"gateway", "cron", "sessions_spawn", "sessions_send",
                     "group:automation", "group:runtime"}
        missing = dangerous - set(deny_list)
        if not missing:
            findings.append(_make_finding("OC-CFG-006", Status.PASS, file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-006", Status.FAIL,
                evidence=f"Missing deny entries: {sorted(missing)}", file_path=fp))

        # OC-CFG-007: Sandbox mode
        sandbox_mode = _deep_get(data, "sandbox", "mode")
        if not sandbox_mode:
            # Check alternative paths
            for agent in _deep_get(data, "agents", default={}).values():
                if isinstance(agent, dict):
                    sandbox_mode = _deep_get(agent, "sandbox", "mode")
                    if sandbox_mode:
                        break
        if sandbox_mode == "all":
            findings.append(_make_finding("OC-CFG-007", Status.PASS, file_path=fp))
        elif sandbox_mode == "non-main":
            findings.append(_make_finding("OC-CFG-007", Status.WARN,
                detail="Sandbox only for non-main agents", file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-007", Status.FAIL,
                evidence=f"sandbox.mode = {sandbox_mode!r}", file_path=fp))

        # OC-CFG-008: Elevated tools
        elevated = _deep_get(data, "tools", "elevated", "enabled")
        if elevated is True:
            findings.append(_make_finding("OC-CFG-008", Status.FAIL,
                evidence="tools.elevated.enabled = true", file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-008", Status.PASS, file_path=fp))

        # OC-CFG-009: DM policy
        dm_policies = []
        channels = _deep_get(data, "channels", default={})
        if isinstance(channels, dict):
            for ch_name, ch_cfg in channels.items():
                if isinstance(ch_cfg, dict):
                    dmp = ch_cfg.get("dmPolicy")
                    if dmp:
                        dm_policies.append((ch_name, dmp))
        if any(p == "open" for _, p in dm_policies):
            findings.append(_make_finding("OC-CFG-009", Status.FAIL,
                evidence=f"Open DM policies: {dm_policies}", file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-009", Status.PASS, file_path=fp))

        # OC-CFG-010: Session DM scope
        dm_scope = _deep_get(data, "session", "dmScope")
        if dm_scope == "per-channel-peer":
            findings.append(_make_finding("OC-CFG-010", Status.PASS, file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-010", Status.FAIL,
                evidence=f"session.dmScope = {dm_scope!r}", file_path=fp))

        # OC-CFG-011: Browser SSRF
        ssrf = _deep_get(data, "browser", "ssrfPolicy",
                         "dangerouslyAllowPrivateNetwork")
        browser_mode = _deep_get(data, "gateway", "nodes", "browser", "mode")
        if browser_mode == "off":
            findings.append(_make_finding("OC-CFG-011", Status.PASS,
                detail="Browser disabled", file_path=fp))
        elif ssrf is True:
            findings.append(_make_finding("OC-CFG-011", Status.FAIL,
                evidence="dangerouslyAllowPrivateNetwork = true", file_path=fp))
        elif ssrf is False:
            findings.append(_make_finding("OC-CFG-011", Status.PASS, file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-011", Status.WARN,
                detail="SSRF policy not explicitly set", file_path=fp))

        # OC-CFG-012: Workspace-only filesystem
        ws_only = _deep_get(data, "tools", "fs", "workspaceOnly")
        if ws_only is True:
            findings.append(_make_finding("OC-CFG-012", Status.PASS, file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-012", Status.FAIL,
                evidence=f"tools.fs.workspaceOnly = {ws_only!r}", file_path=fp))

        # OC-CFG-013: Container namespace join
        ns_join = _deep_get(data, "dangerouslyAllowContainerNamespaceJoin")
        if ns_join is None:
            ns_join = _deep_get(data, "sandbox", "docker",
                                "dangerouslyAllowContainerNamespaceJoin")
        if ns_join is True:
            findings.append(_make_finding("OC-CFG-013", Status.FAIL,
                evidence="dangerouslyAllowContainerNamespaceJoin = true",
                file_path=fp))
        else:
            findings.append(_make_finding("OC-CFG-013", Status.PASS, file_path=fp))

    return findings
