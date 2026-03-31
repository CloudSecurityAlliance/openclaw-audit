"""Credential hygiene checks (OC-CRED-001 through OC-CRED-004)."""

from __future__ import annotations

import re
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


# Patterns that look like API keys/tokens
_SECRET_PATTERNS = [
    # Generic patterns
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
     "API key"),
    (r'(?:secret[_-]?key|secretkey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
     "Secret key"),
    (r'(?:auth[_-]?token|authtoken|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
     "Auth token"),
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})',
     "Password"),
    # Provider-specific
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API key"),
    (r'sk-ant-[a-zA-Z0-9\-]{20,}', "Anthropic API key"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub personal access token"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth token"),
    (r'glpat-[a-zA-Z0-9\-_]{20,}', "GitLab personal access token"),
    (r'xoxb-[0-9]{10,}-[a-zA-Z0-9]+', "Slack bot token"),
    (r'xoxp-[0-9]{10,}-[a-zA-Z0-9]+', "Slack user token"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API key"),
    (r'npm_[a-zA-Z0-9]{36}', "npm token"),
]

_SECRET_RE = [(re.compile(p, re.IGNORECASE), d) for p, d in _SECRET_PATTERNS]


def _scan_for_secrets(content: str) -> list[tuple[str, str]]:
    """Return list of (type, redacted_match) for found secrets."""
    hits = []
    for pat, desc in _SECRET_RE:
        for m in pat.finditer(content):
            value = m.group(0)
            redacted = value[:8] + "..." + value[-4:] if len(value) > 16 else value[:4] + "..."
            hits.append((desc, redacted))
    return hits


def run(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    # OC-CRED-001: API keys in config files
    config_secrets = []
    for cfg_path in ctx.config_files:
        try:
            content = cfg_path.read_text(encoding="utf-8", errors="replace")
            hits = _scan_for_secrets(content)
            for desc, redacted in hits:
                config_secrets.append((str(cfg_path), desc, redacted))
        except OSError:
            pass

    if config_secrets:
        evidence = "; ".join(
            f"{p}: {d} ({r})" for p, d, r in config_secrets[:5]
        )
        findings.append(_make("OC-CRED-001", Status.FAIL,
            evidence=evidence))
    else:
        findings.append(_make("OC-CRED-001", Status.PASS))

    # OC-CRED-002: API keys in .env files
    env_secrets = []
    for env_path in ctx.env_files:
        try:
            content = env_path.read_text(encoding="utf-8", errors="replace")
            hits = _scan_for_secrets(content)
            for desc, redacted in hits:
                env_secrets.append((str(env_path), desc, redacted))
        except OSError:
            pass

    if env_secrets:
        evidence = "; ".join(
            f"{p}: {d} ({r})" for p, d, r in env_secrets[:5]
        )
        findings.append(_make("OC-CRED-002", Status.FAIL, evidence=evidence))
    elif not ctx.env_files:
        findings.append(_make("OC-CRED-002", Status.SKIP,
            detail="No .env files found"))
    else:
        findings.append(_make("OC-CRED-002", Status.PASS))

    # OC-CRED-003: Credentials in session transcripts
    session_secrets = []
    for sd in ctx.session_dirs:
        for f in sd.rglob("*.jsonl"):
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                hits = _scan_for_secrets(content)
                if hits:
                    session_secrets.append((str(f), len(hits)))
            except OSError:
                pass
            if len(session_secrets) >= 5:
                break

    if session_secrets:
        evidence = "; ".join(f"{p}: {n} secret(s)" for p, n in session_secrets)
        findings.append(_make("OC-CRED-003", Status.FAIL, evidence=evidence))
    elif not ctx.session_dirs:
        findings.append(_make("OC-CRED-003", Status.SKIP,
            detail="No session directories found"))
    else:
        findings.append(_make("OC-CRED-003", Status.PASS))

    # OC-CRED-004: Standing long-lived API keys (no JIT/rotation/vault)
    _VAULT_INDICATORS = re.compile(
        r'vault://|vault\.hashicorp|secretsmanager|'
        r'keychain|credential[_-]?helper|'
        r'sts\.amazonaws|workload.?identity|'
        r'managed.?identity|ttl|rotation|ephemeral',
        re.IGNORECASE,
    )
    standing_keys: list[tuple[str, str]] = []
    for cfg_path in ctx.config_files:
        try:
            content = cfg_path.read_text(encoding="utf-8", errors="replace")
            # Only flag if we found secrets AND no vault/rotation indicators
            if _scan_for_secrets(content) and not _VAULT_INDICATORS.search(content):
                standing_keys.append((str(cfg_path), "static credentials without JIT/vault"))
        except OSError:
            pass
    for env_path in ctx.env_files:
        try:
            content = env_path.read_text(encoding="utf-8", errors="replace")
            if _scan_for_secrets(content) and not _VAULT_INDICATORS.search(content):
                standing_keys.append((str(env_path), "static credentials in .env"))
        except OSError:
            pass

    if standing_keys:
        evidence = "; ".join(f"{p}: {d}" for p, d in standing_keys[:5])
        findings.append(_make("OC-CRED-004", Status.FAIL, evidence=evidence))
    elif not ctx.config_files and not ctx.env_files:
        findings.append(_make("OC-CRED-004", Status.SKIP,
            detail="No config or .env files found"))
    else:
        findings.append(_make("OC-CRED-004", Status.PASS))

    return findings
