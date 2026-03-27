"""Docker sandbox audit checks (OC-DOCK-001 through OC-DOCK-007, OC-NET-001)."""

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


DANGEROUS_MOUNTS = [
    "/var/run/docker.sock", "/run/docker.sock",
    "/etc", "/proc", "/sys", "/dev",
    "/root", "/home",
    ".ssh", ".gnupg", ".aws", ".kube", ".docker",
    "Keychains", ".password-store",
]


def _parse_yaml_lite(text: str) -> dict[str, Any]:
    """Minimal YAML-like extraction for docker-compose files.
    Not a full parser — extracts what we need for security checks."""
    result: dict[str, Any] = {"_raw": text}

    # Check for key patterns we care about
    if re.search(r'privileged:\s*true', text, re.IGNORECASE):
        result["privileged"] = True
    if re.search(r'network_mode:\s*["\']?host', text, re.IGNORECASE):
        result["network_host"] = True
    if re.search(r'read_only:\s*true', text, re.IGNORECASE):
        result["read_only"] = True

    # cap_drop
    cap_drop_match = re.search(r'cap_drop:\s*\n((?:\s+-\s+\w+\n?)+)', text)
    if cap_drop_match:
        result["cap_drop"] = re.findall(r'-\s+(\w+)', cap_drop_match.group(1))

    # volumes/binds
    volume_lines = re.findall(r'-\s+["\']?([^"\':\n]+:[^"\':\n]+)', text)
    result["volumes"] = volume_lines

    # user
    user_match = re.search(r'user:\s*["\']?(\S+)', text)
    if user_match:
        result["user"] = user_match.group(1)

    # seccomp/apparmor
    if re.search(r'seccomp[=:]\s*unconfined', text, re.IGNORECASE):
        result["seccomp_unconfined"] = True
    if re.search(r'apparmor[=:]\s*unconfined', text, re.IGNORECASE):
        result["apparmor_unconfined"] = True

    # seccomp profile configured
    if re.search(r'seccomp', text, re.IGNORECASE) and "seccomp_unconfined" not in result:
        result["has_seccomp"] = True

    return result


def _check_docker_compose(path: Path, findings: list[Finding]) -> None:
    """Check a docker-compose YAML file."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    fp = str(path)
    info = _parse_yaml_lite(text)

    # OC-DOCK-001: cap_drop
    if "cap_drop" in info and "ALL" in [c.upper() for c in info["cap_drop"]]:
        findings.append(_make("OC-DOCK-001", Status.PASS, file_path=fp))
    else:
        findings.append(_make("OC-DOCK-001", Status.FAIL,
            evidence="No cap_drop: ALL found", file_path=fp))

    # OC-DOCK-002: read_only
    if info.get("read_only"):
        findings.append(_make("OC-DOCK-002", Status.PASS, file_path=fp))
    else:
        findings.append(_make("OC-DOCK-002", Status.FAIL,
            evidence="read_only not set to true", file_path=fp))

    # OC-DOCK-003: seccomp
    if info.get("has_seccomp") or info.get("seccomp_unconfined"):
        if info.get("seccomp_unconfined"):
            pass  # Handled by OC-DOCK-007
        else:
            findings.append(_make("OC-DOCK-003", Status.PASS, file_path=fp))
    else:
        findings.append(_make("OC-DOCK-003", Status.FAIL,
            evidence="No seccomp profile configured", file_path=fp))

    # OC-DOCK-004: Dangerous bind mounts
    dangerous_found = []
    for vol in info.get("volumes", []):
        host_part = vol.split(":")[0]
        for dm in DANGEROUS_MOUNTS:
            if dm in host_part:
                dangerous_found.append(vol)
                break
    if dangerous_found:
        findings.append(_make("OC-DOCK-004", Status.FAIL,
            evidence=f"Dangerous mounts: {dangerous_found[:5]}", file_path=fp))
    else:
        findings.append(_make("OC-DOCK-004", Status.PASS, file_path=fp))

    # OC-DOCK-005: Root user
    user = info.get("user")
    if user and user != "root" and user != "0":
        findings.append(_make("OC-DOCK-005", Status.PASS,
            detail=f"user: {user}", file_path=fp))
    elif user in ("root", "0"):
        findings.append(_make("OC-DOCK-005", Status.FAIL,
            evidence="Container explicitly runs as root", file_path=fp))
    else:
        findings.append(_make("OC-DOCK-005", Status.WARN,
            detail="No user specified (defaults to root)", file_path=fp))

    # OC-DOCK-006: Privileged
    if info.get("privileged"):
        findings.append(_make("OC-DOCK-006", Status.FAIL,
            evidence="privileged: true", file_path=fp))
    else:
        findings.append(_make("OC-DOCK-006", Status.PASS, file_path=fp))

    # OC-DOCK-007: Unconfined profiles
    if info.get("seccomp_unconfined") or info.get("apparmor_unconfined"):
        ev_parts = []
        if info.get("seccomp_unconfined"):
            ev_parts.append("seccomp=unconfined")
        if info.get("apparmor_unconfined"):
            ev_parts.append("apparmor=unconfined")
        findings.append(_make("OC-DOCK-007", Status.FAIL,
            evidence=", ".join(ev_parts), file_path=fp))
    else:
        findings.append(_make("OC-DOCK-007", Status.PASS, file_path=fp))

    # OC-NET-001: Host network
    if info.get("network_host"):
        findings.append(_make("OC-NET-001", Status.FAIL,
            evidence="network_mode: host", file_path=fp))
    else:
        findings.append(_make("OC-NET-001", Status.PASS, file_path=fp))


def _check_openclaw_docker_config(ctx: ScanContext, findings: list[Finding]) -> None:
    """Check Docker sandbox settings in OpenClaw config files."""
    for cfg_path in ctx.config_files:
        try:
            text = cfg_path.read_text(encoding="utf-8", errors="replace")
            text = re.sub(r'(?m)^\s*//.*$', '', text)
            text = re.sub(r',\s*([}\]])', r'\1', text)
            data = json.loads(text)
        except (json.JSONDecodeError, OSError):
            continue

        fp = str(cfg_path)
        sandbox = data.get("sandbox", {}).get("docker", {})
        if not sandbox:
            # Check per-agent
            for agent in data.get("agents", {}).values():
                if isinstance(agent, dict):
                    sandbox = agent.get("sandbox", {}).get("docker", {})
                    if sandbox:
                        break

        if not sandbox:
            continue

        # Check binds for dangerous mounts
        binds = sandbox.get("binds", [])
        dangerous = []
        for b in binds:
            src = b.split(":")[0] if isinstance(b, str) else ""
            for dm in DANGEROUS_MOUNTS:
                if dm in src:
                    dangerous.append(b)
                    break
        if dangerous:
            findings.append(_make("OC-DOCK-004", Status.FAIL,
                evidence=f"Config binds: {dangerous[:5]}", file_path=fp))

        # Check network mode
        network = sandbox.get("network", "")
        if network == "host":
            findings.append(_make("OC-NET-001", Status.FAIL,
                evidence="sandbox.docker.network = 'host'", file_path=fp))

        # Check seccomp/apparmor unconfined
        if sandbox.get("seccompProfile") == "unconfined":
            findings.append(_make("OC-DOCK-007", Status.FAIL,
                evidence="sandbox.docker.seccompProfile = 'unconfined'",
                file_path=fp))
        if sandbox.get("apparmorProfile") == "unconfined":
            findings.append(_make("OC-DOCK-007", Status.FAIL,
                evidence="sandbox.docker.apparmorProfile = 'unconfined'",
                file_path=fp))


def run(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    has_docker = bool(ctx.docker_files)

    if ctx.docker_files:
        for df in ctx.docker_files:
            if df.name.startswith("docker-compose"):
                _check_docker_compose(df, findings)

    # Also check OpenClaw config for Docker sandbox settings
    _check_openclaw_docker_config(ctx, findings)

    if not has_docker and not any(f.check_id.startswith("OC-DOCK") for f in findings):
        for cid in [f"OC-DOCK-{i:03d}" for i in range(1, 8)]:
            findings.append(_make(cid, Status.SKIP,
                detail="No Docker configuration found"))
        findings.append(_make("OC-NET-001", Status.SKIP,
            detail="No Docker configuration found"))

    return findings
