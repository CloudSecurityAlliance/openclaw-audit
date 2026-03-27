"""Auto-detect whether target is an installed OpenClaw instance, git repo, or hybrid."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

from .models import ContextType, ScanContext


def detect_context(target: Path) -> ScanContext:
    """Scan a target path and build a ScanContext describing what we found."""
    ctx = ScanContext(target_path=target.resolve())

    if not target.exists():
        ctx.context_type = ContextType.UNKNOWN
        return ctx

    is_instance = _looks_like_instance(target)
    is_repo = _looks_like_repo(target)

    if is_instance and is_repo:
        ctx.context_type = ContextType.HYBRID
    elif is_instance:
        ctx.context_type = ContextType.INSTALLED_INSTANCE
    elif is_repo:
        ctx.context_type = ContextType.GIT_REPO
    else:
        ctx.context_type = ContextType.UNKNOWN

    # Discover all security-relevant files
    _discover_configs(ctx, target)
    _discover_soul_files(ctx, target)
    _discover_skills(ctx, target)
    _discover_mcp(ctx, target)
    _discover_docker(ctx, target)
    _discover_env(ctx, target)
    _discover_agents(ctx, target)
    _discover_nemoclaw(ctx, target)
    _detect_version(ctx, target)

    return ctx


def _looks_like_instance(p: Path) -> bool:
    """Does this look like ~/.openclaw/ or an installed OpenClaw instance?"""
    markers = ["agents", "config.json", "config.json5", "config.jsonc"]
    for m in markers:
        if (p / m).exists():
            return True
    # Check if it's ~/.openclaw itself
    if p.name in (".openclaw", ".clawdbot", "openclaw"):
        return True
    return False


def _looks_like_repo(p: Path) -> bool:
    """Does this look like a git repo or deployment configuration?"""
    markers = [
        ".git", "docker-compose.yml", "docker-compose.yaml",
        "Dockerfile", "package.json", "nemoclaw-blueprint",
    ]
    for m in markers:
        if (p / m).exists():
            return True
    return False


def _discover_configs(ctx: ScanContext, root: Path) -> None:
    """Find OpenClaw config files."""
    config_patterns = [
        "config.json", "config.json5", "config.jsonc",
        "openclaw.config.json", "openclaw.config.json5",
        "**/config.json", "**/config.json5",
    ]
    for pattern in config_patterns:
        for f in root.glob(pattern):
            if f.is_file() and f not in ctx.config_files:
                ctx.config_files.append(f)

    # Also check agents subdirectories
    for f in root.glob("agents/*/config.json*"):
        if f.is_file() and f not in ctx.config_files:
            ctx.config_files.append(f)


def _discover_soul_files(ctx: ScanContext, root: Path) -> None:
    """Find SOUL.md and HEARTBEAT.md files."""
    for pattern in ["**/SOUL.md", "**/soul.md"]:
        for f in root.glob(pattern):
            if f.is_file():
                ctx.soul_files.append(f)
    for pattern in ["**/HEARTBEAT.md", "**/heartbeat.md"]:
        for f in root.glob(pattern):
            if f.is_file():
                ctx.heartbeat_files.append(f)


def _discover_skills(ctx: ScanContext, root: Path) -> None:
    """Find skill directories and SKILL.md files."""
    for f in root.glob("**/SKILL.md"):
        if f.is_file():
            ctx.skill_files.append(f)
            if f.parent not in ctx.skill_dirs:
                ctx.skill_dirs.append(f.parent)

    # Also scan skills/ or custom_skills/ directories
    for d in root.glob("**/skills"):
        if d.is_dir() and d not in ctx.skill_dirs:
            ctx.skill_dirs.append(d)
    for d in root.glob("**/custom_skills"):
        if d.is_dir() and d not in ctx.skill_dirs:
            ctx.skill_dirs.append(d)


def _discover_mcp(ctx: ScanContext, root: Path) -> None:
    """Find MCP configuration files."""
    mcp_patterns = [
        "**/mcp.json", "**/mcp.json5", "**/mcp-config.json",
        "**/.mcp.json", "**/mcp-servers.json",
    ]
    for pattern in mcp_patterns:
        for f in root.glob(pattern):
            if f.is_file():
                ctx.mcp_config_files.append(f)


def _discover_docker(ctx: ScanContext, root: Path) -> None:
    """Find Docker-related files."""
    docker_patterns = [
        "docker-compose.yml", "docker-compose.yaml",
        "Dockerfile", "**/Dockerfile",
        "docker-compose.*.yml", "docker-compose.*.yaml",
    ]
    for pattern in docker_patterns:
        for f in root.glob(pattern):
            if f.is_file():
                ctx.docker_files.append(f)


def _discover_env(ctx: ScanContext, root: Path) -> None:
    """Find .env files."""
    for pattern in [".env", ".env.*", "**/.env", "**/.env.*"]:
        for f in root.glob(pattern):
            if f.is_file() and ".git" not in str(f):
                ctx.env_files.append(f)


def _discover_agents(ctx: ScanContext, root: Path) -> None:
    """Find agent directories with sessions and memory."""
    for d in root.glob("agents/*"):
        if d.is_dir():
            ctx.agent_dirs.append(d)
    for d in root.glob("**/memory"):
        if d.is_dir():
            ctx.memory_dirs.append(d)
    for d in root.glob("**/sessions"):
        if d.is_dir():
            ctx.session_dirs.append(d)


def _discover_nemoclaw(ctx: ScanContext, root: Path) -> None:
    """Detect NemoClaw presence."""
    nemoclaw_markers = [
        "nemoclaw-blueprint", "nemoclaw.yaml", "nemoclaw.yml",
        ".nemoclaw",
    ]
    for m in nemoclaw_markers:
        if (root / m).exists():
            ctx.is_nemoclaw = True
            break

    for f in root.glob("**/openclaw-sandbox.yaml"):
        ctx.nemoclaw_policy_files.append(f)
    for f in root.glob("**/nemoclaw*.yaml"):
        if f.is_file():
            ctx.nemoclaw_policy_files.append(f)


def _detect_version(ctx: ScanContext, root: Path) -> None:
    """Try to determine the OpenClaw version."""
    # Check package.json
    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text())
            ver = data.get("version")
            if ver:
                ctx.openclaw_version = ver
                return
        except (json.JSONDecodeError, OSError):
            pass

    # Check node_modules
    for p in root.glob("**/node_modules/@openclaw/*/package.json"):
        try:
            data = json.loads(p.read_text())
            ver = data.get("version")
            if ver:
                ctx.openclaw_version = ver
                return
        except (json.JSONDecodeError, OSError):
            pass

    # Try CLI
    try:
        result = subprocess.run(
            ["openclaw", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            ctx.openclaw_version = result.stdout.strip().split()[-1]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
