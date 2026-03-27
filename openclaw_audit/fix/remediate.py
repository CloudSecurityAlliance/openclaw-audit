"""Auto-fix engine with three fix levels: basic, medium, complete."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any

from ..models import Finding, FixLevel, ScanContext, Status


def apply_fixes(ctx: ScanContext, findings: list[Finding],
                fix_level: FixLevel, dry_run: bool = False) -> list[str]:
    """Apply fixes up to the given level. Returns a list of actions taken."""
    actions: list[str] = []

    fixable = [f for f in findings
               if f.status == Status.FAIL
               and f.fix_level is not None
               and _level_value(f.fix_level) <= _level_value(fix_level)]

    for f in fixable:
        action = _apply_fix(ctx, f, dry_run)
        if action:
            actions.append(action)
            f.fix_applied = not dry_run
            f.fix_description = action

    return actions


def _level_value(level: FixLevel) -> int:
    return {FixLevel.BASIC: 1, FixLevel.MEDIUM: 2, FixLevel.COMPLETE: 3}[level]


def _apply_fix(ctx: ScanContext, finding: Finding, dry_run: bool) -> str | None:
    """Dispatch to the appropriate fix function."""
    dispatch = {
        "OC-SOUL-001": _fix_soul_permissions,
        "OC-SOUL-007": _fix_heartbeat_permissions,
        "OC-PERM-001": _fix_dir_permissions,
        "OC-PERM-002": _fix_file_permissions,
        "OC-CFG-001": _fix_config_auth,
        "OC-CFG-002": _fix_config_bind,
        "OC-CFG-003": _fix_config_mdns,
        "OC-CFG-004": _fix_config_exec_security,
        "OC-CFG-005": _fix_config_exec_ask,
        "OC-CFG-006": _fix_config_deny_tools,
        "OC-CFG-007": _fix_config_sandbox,
        "OC-CFG-008": _fix_config_elevated,
        "OC-CFG-009": _fix_config_dm_policy,
        "OC-CFG-010": _fix_config_dm_scope,
        "OC-CFG-011": _fix_config_ssrf,
        "OC-CFG-012": _fix_config_workspace_only,
        "OC-CFG-013": _fix_config_namespace_join,
        "OC-SKILL-001": _fix_quarantine_skill,
        "OC-SKILL-002": _fix_quarantine_skill,
        "OC-SKILL-003": _fix_quarantine_skill,
        "OC-SKILL-004": _fix_quarantine_skill,
        "OC-SKILL-006": _fix_quarantine_skill,
    }

    handler = dispatch.get(finding.check_id)
    if handler:
        return handler(ctx, finding, dry_run)
    return None


# ── Basic fixes ──────────────────────────────────────────────────────────

def _fix_soul_permissions(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path = Path(f.file_path) if f.file_path else None
    if not path or not path.exists():
        return f"[skip] SOUL.md not found at {f.file_path}"
    if dry_run:
        return f"[dry-run] Would set {path} to read-only (444)"
    os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    return f"Set {path} to read-only (444)"


def _fix_heartbeat_permissions(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path = Path(f.file_path) if f.file_path else None
    if not path or not path.exists():
        return f"[skip] HEARTBEAT.md not found"
    if dry_run:
        return f"[dry-run] Would set {path} to read-only (444)"
    os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    return f"Set {path} to read-only (444)"


def _fix_dir_permissions(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path = ctx.target_path
    if dry_run:
        return f"[dry-run] Would set {path} to 700"
    os.chmod(path, stat.S_IRWXU)
    return f"Set {path} to 700"


def _fix_file_permissions(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    fixed = []
    for pattern in ("auth-profiles.json", "credentials.json", "config.json",
                    "config.json5", "*.key", "*.pem"):
        for fp in ctx.target_path.rglob(pattern):
            if fp.is_file():
                mode = fp.stat().st_mode & 0o777
                if mode & 0o077:
                    if not dry_run:
                        os.chmod(fp, stat.S_IRUSR | stat.S_IWUSR)
                    fixed.append(str(fp))
    prefix = "[dry-run] Would fix" if dry_run else "Fixed"
    return f"{prefix} permissions on {len(fixed)} file(s) to 600"


# ── Medium fixes (config modifications) ──────────────────────────────────

def _load_and_backup_config(ctx: ScanContext, f: Finding) -> tuple[Path | None, dict | None]:
    """Find the config file and load it."""
    path = Path(f.file_path) if f.file_path else None
    if not path or not path.exists():
        # Try first config file
        if ctx.config_files:
            path = ctx.config_files[0]
        else:
            return None, None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        text = re.sub(r'(?m)^\s*//.*$', '', text)
        text = re.sub(r',\s*([}\]])', r'\1', text)
        return path, json.loads(text)
    except (json.JSONDecodeError, OSError):
        return None, None


def _save_config(path: Path, data: dict, dry_run: bool) -> None:
    if dry_run:
        return
    # Backup
    backup = path.with_suffix(path.suffix + ".bak")
    if not backup.exists():
        shutil.copy2(path, backup)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _ensure_nested(d: dict, *keys: str) -> dict:
    """Ensure nested dict path exists, return innermost dict."""
    for k in keys:
        if k not in d or not isinstance(d[k], dict):
            d[k] = {}
        d = d[k]
    return d


def _fix_config_auth(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    import secrets
    token = secrets.token_urlsafe(32)
    gw = _ensure_nested(data, "gateway", "auth")
    gw["mode"] = "token"
    gw["token"] = token
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Set gateway.auth.mode='token' with generated 32-char token"


def _fix_config_bind(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    gw = _ensure_nested(data, "gateway")
    gw["bind"] = "loopback"
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Set gateway.bind='loopback'"


def _fix_config_mdns(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    mdns = _ensure_nested(data, "discovery", "mdns")
    mdns["mode"] = "off"
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Set discovery.mdns.mode='off'"


def _fix_config_exec_security(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    ex = _ensure_nested(data, "tools", "exec")
    ex["security"] = "deny"
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Set tools.exec.security='deny'"


def _fix_config_exec_ask(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    ex = _ensure_nested(data, "tools", "exec")
    ex["ask"] = "always"
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Set tools.exec.ask='always'"


def _fix_config_deny_tools(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    tools = _ensure_nested(data, "tools")
    deny = set(tools.get("deny", []))
    deny.update(["gateway", "cron", "sessions_spawn", "sessions_send",
                 "group:automation", "group:runtime"])
    tools["deny"] = sorted(deny)
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Added dangerous tools to deny list"


def _fix_config_sandbox(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    sb = _ensure_nested(data, "sandbox")
    sb["mode"] = "all"
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Set sandbox.mode='all'"


def _fix_config_elevated(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    el = _ensure_nested(data, "tools", "elevated")
    el["enabled"] = False
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Set tools.elevated.enabled=false"


def _fix_config_dm_policy(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    channels = data.get("channels", {})
    for ch_name, ch_cfg in channels.items():
        if isinstance(ch_cfg, dict) and ch_cfg.get("dmPolicy") == "open":
            ch_cfg["dmPolicy"] = "pairing"
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Changed dmPolicy from 'open' to 'pairing'"


def _fix_config_dm_scope(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    session = _ensure_nested(data, "session")
    session["dmScope"] = "per-channel-peer"
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Set session.dmScope='per-channel-peer'"


def _fix_config_ssrf(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    browser = _ensure_nested(data, "browser", "ssrfPolicy")
    browser["dangerouslyAllowPrivateNetwork"] = False
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Set dangerouslyAllowPrivateNetwork=false"


def _fix_config_workspace_only(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    fs = _ensure_nested(data, "tools", "fs")
    fs["workspaceOnly"] = True
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Set tools.fs.workspaceOnly=true"


def _fix_config_namespace_join(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    path, data = _load_and_backup_config(ctx, f)
    if not data:
        return "[skip] Could not load config"
    data["dangerouslyAllowContainerNamespaceJoin"] = False
    sb = data.get("sandbox", {}).get("docker", {})
    if "dangerouslyAllowContainerNamespaceJoin" in sb:
        sb["dangerouslyAllowContainerNamespaceJoin"] = False
    _save_config(path, data, dry_run)
    prefix = "[dry-run]" if dry_run else "Applied"
    return f"{prefix} Set dangerouslyAllowContainerNamespaceJoin=false"


# ── Complete fixes ───────────────────────────────────────────────────────

def _fix_quarantine_skill(ctx: ScanContext, f: Finding, dry_run: bool) -> str:
    """Move a suspicious skill to a quarantine directory."""
    path = Path(f.file_path) if f.file_path else None
    if not path:
        return "[skip] No file path for skill"
    skill_dir = path.parent if path.name == "SKILL.md" else path
    if not skill_dir.is_dir():
        return f"[skip] Skill directory not found: {skill_dir}"

    quarantine = ctx.target_path / ".quarantine"
    dest = quarantine / skill_dir.name

    if dry_run:
        return f"[dry-run] Would quarantine {skill_dir} -> {dest}"

    quarantine.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.move(str(skill_dir), str(dest))
    return f"Quarantined {skill_dir} -> {dest}"
