"""Capability model — a normalized intermediate representation of the risky
capabilities an asset (skill, MCP server, config, deployment) exposes.

This is the substrate the correlated attack-path checks (OC-PATH-*) reason over:
instead of reporting isolated facts ("reads .env", "makes HTTP calls") it lets
the auditor ask "does the same asset that reads secrets also egress data?".
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .models import ScanContext


# --- Bounded text collection ----------------------------------------------
# Reading and regex-scanning an entire repo can hang on large/vendored/minified
# trees. These caps keep scans bounded (the batch scanner once stalled 47 min
# on a single "marketplace" repo before this guard existed).
_TEXT_EXTS = {".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml"}
_SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "vendor", ".venv", "venv",
    "__pycache__", ".next", "target", ".cache", "bower_components",
}
_SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".lock", ".bundle.js")
_MAX_FILE_BYTES = 256 * 1024        # skip any single file larger than this
_MAX_TOTAL_BYTES = 4 * 1024 * 1024  # stop after this much text per asset


def collect_text(directory: Path, max_total: int = _MAX_TOTAL_BYTES) -> str:
    """Concatenate text from a directory tree, pruning vendored dirs and
    skipping oversized/minified files, capped at *max_total* bytes."""
    chunks: list[str] = []
    total = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if total >= max_total:
                return "".join(chunks)
            if os.path.splitext(fn)[1].lower() not in _TEXT_EXTS:
                continue
            if fn.endswith(_SKIP_SUFFIXES):
                continue
            fp = os.path.join(root, fn)
            try:
                if os.path.getsize(fp) > _MAX_FILE_BYTES:
                    continue
                with open(fp, encoding="utf-8", errors="replace") as f:
                    txt = f.read(max_total - total + 1)
            except OSError:
                continue
            chunks.append(txt)
            chunks.append("\n")
            total += len(txt)
    return "".join(chunks)


# ---------------------------------------------------------------------------
# Capability taxonomy (string constants — kept stable for JSON output)
# ---------------------------------------------------------------------------

READ_FILE = "read_file"
WRITE_FILE = "write_file"
SHELL_EXEC = "shell_exec"
NETWORK_GET = "network_get"
NETWORK_POST = "network_post"
ENV_READ = "env_read"
CREDENTIAL_READ = "credential_read"
SSH_KEY_READ = "ssh_key_read"
CLOUD_TOKEN_READ = "cloud_token_read"
SESSION_TRANSCRIPT_READ = "session_transcript_read"
SESSION_TRANSCRIPT_WRITE = "session_transcript_write"
PACKAGE_INSTALL = "package_install"
REMOTE_CODE_DOWNLOAD = "remote_code_download"
BROWSER_PRIVATE_NETWORK = "browser_private_network"
EMAIL_SEND = "email_send"
WEBHOOK_CALL = "webhook_call"
MCP_TOOL_CALL = "mcp_tool_call"

# Capabilities that constitute reading something sensitive.
SENSITIVE_READ_CAPS = frozenset({
    ENV_READ, CREDENTIAL_READ, SSH_KEY_READ, CLOUD_TOKEN_READ,
    SESSION_TRANSCRIPT_READ,
})
# Capabilities that move data off the asset / out to a network.
EGRESS_CAPS = frozenset({
    NETWORK_POST, NETWORK_GET, WEBHOOK_CALL, EMAIL_SEND, REMOTE_CODE_DOWNLOAD,
})


# (capability, regex) — first match adds the capability.
_CAP_PATTERNS: list[tuple[str, str]] = [
    (READ_FILE, r'\bopen\s*\([^)]*[\'"]r'),
    (READ_FILE, r'\.read_text\s*\(|\.readFile\b|readFileSync\b|\bcat\s+'),
    (WRITE_FILE, r'\bopen\s*\([^)]*[\'"][wa]'),
    (WRITE_FILE, r'\.write_text\s*\(|\.writeFile\b|writeFileSync\b|>>?\s'),
    (SHELL_EXEC, r'\bos\.system\s*\(|\bsubprocess\.|child_process|\bexec\s*\('
                 r'|\bspawn\s*\(|execSync\s*\(|`[^`]*\$\('),
    (NETWORK_GET, r'requests\.get\s*\(|fetch\s*\(\s*[\'"]http|axios\.get\s*\('
                  r'|urllib\.request|\bwget\s+|\bcurl\s+(?!.*\|)'),
    (NETWORK_POST, r'requests\.(post|put|patch)\s*\(|axios\.(post|put|patch)\s*\('
                   r'|fetch\s*\([^)]*method\s*:\s*[\'"]POST|\.send\s*\('),
    (ENV_READ, r'os\.environ|process\.env|getenv\s*\(|\.env\b|dotenv'),
    (CREDENTIAL_READ, r'\.aws/credentials|\.kube/config|\.docker/config'
                      r'|Keychain|password[-_]?store|wallet\.dat'
                      r'|Chrome.*(?:Login|Cookies)|\.npmrc|\.pypirc'),
    (SSH_KEY_READ, r'\.ssh/|id_rsa|id_ed25519|id_ecdsa|\.gnupg'),
    (CLOUD_TOKEN_READ, r'AWS_SECRET|AWS_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS'
                       r'|AZURE_|GCP_|gcloud auth'),
    (SESSION_TRANSCRIPT_READ, r'transcript|session[._-]?log|sessions/.*\.(json|md)'),
    (SESSION_TRANSCRIPT_WRITE, r'(write|append|save|export).{0,20}transcript'),
    (PACKAGE_INSTALL, r'pip\s+install|npm\s+(i|install)\b|yarn\s+add|pnpm\s+add'
                      r'|apt(-get)?\s+install'),
    (REMOTE_CODE_DOWNLOAD, r'(?:curl|wget)\s+[^\n|]*\|\s*(?:bash|sh|python|node)'
                           r'|hxxps?://'),
    (EMAIL_SEND, r'smtplib|sendmail|sendgrid|nodemailer|\.send_message\s*\('
                 r'|mailgun'),
    (WEBHOOK_CALL, r'webhook|hooks\.slack\.com|discord\.com/api/webhooks'),
    (MCP_TOOL_CALL, r'mcp[._-]?(?:tool|call|client)|callTool\s*\('),
]

# Sensitive sources referenced in text (path-like markers).
_SOURCE_PATTERNS: list[tuple[str, str]] = [
    (".env", r'\.env\b'),
    (".ssh", r'\.ssh/|id_rsa|id_ed25519'),
    (".aws/credentials", r'\.aws/credentials|AWS_SECRET|AWS_ACCESS_KEY'),
    (".kube/config", r'\.kube/config'),
    ("session transcript", r'transcript|session[._-]?log'),
    ("browser cookies", r'Cookies|cookies\.sqlite'),
    ("github token", r'GITHUB_TOKEN|ghp_[A-Za-z0-9]'),
    ("slack token", r'xox[bap]-|SLACK_TOKEN'),
    ("api key", r'api[_-]?key|secret[_-]?key'),
]

_URL_RE = re.compile(r'https?://[^\s\'"<>)]+', re.IGNORECASE)
_PRIVATE_HOST_RE = re.compile(
    r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|'
    r'10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|'
    r'169\.254\.\d+\.\d+|169\.254\.169\.254)',
    re.IGNORECASE,
)
_PASTE_SINK_RE = re.compile(
    r'pastebin\.com|hastebin|ix\.io|transfer\.sh|0x0\.st|requestbin'
    r'|webhook\.site|ngrok\.io|\.vercel\.app',
    re.IGNORECASE,
)


@dataclass
class CapabilityProfile:
    """Normalized capability summary for one asset."""

    asset: str
    asset_type: str  # skill | mcp_server | config | deployment
    capabilities: set[str] = field(default_factory=set)
    sensitive_sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    declared_inputs: list[str] = field(default_factory=list)
    trust_boundary: str = "unknown"
    file_path: str = ""

    @property
    def risk_paths(self) -> list[str]:
        """Coarse intra-asset risk paths derived from capabilities present.

        Authoritative cross-evidence correlation lives in the OC-PATH checks;
        this is a convenience summary for the JSON output and triage.
        """
        paths = []
        has_sensitive = bool(self.capabilities & SENSITIVE_READ_CAPS) \
            or bool(self.sensitive_sources)
        has_egress = bool(self.capabilities & EGRESS_CAPS)
        if has_sensitive and has_egress:
            paths.append("sensitive_source -> network_egress")
        if SESSION_TRANSCRIPT_READ in self.capabilities and has_egress:
            paths.append("session_transcript -> network_egress")
        if REMOTE_CODE_DOWNLOAD in self.capabilities:
            paths.append("remote_download -> execution")
        if SHELL_EXEC in self.capabilities and (
            NETWORK_GET in self.capabilities or NETWORK_POST in self.capabilities
        ):
            paths.append("network_input -> shell_exec")
        return paths

    def has_egress(self) -> bool:
        return bool(self.capabilities & EGRESS_CAPS) or bool(self.sinks)

    def reads_secrets(self) -> bool:
        return bool(self.capabilities & SENSITIVE_READ_CAPS) \
            or bool(self.sensitive_sources)

    def to_dict(self) -> dict:
        return {
            "asset": self.asset,
            "asset_type": self.asset_type,
            "capabilities": sorted(self.capabilities),
            "sensitive_sources": self.sensitive_sources,
            "sinks": self.sinks,
            "declared_inputs": self.declared_inputs,
            "trust_boundary": self.trust_boundary,
            "risk_paths": self.risk_paths,
            "file_path": self.file_path,
        }


_FLAGS = re.IGNORECASE | re.MULTILINE


def extract_capabilities(content: str) -> set[str]:
    caps: set[str] = set()
    for cap, pat in _CAP_PATTERNS:
        if cap in caps:
            continue
        if re.search(pat, content, _FLAGS):
            caps.add(cap)
    return caps


def extract_sensitive_sources(content: str) -> list[str]:
    found = []
    for name, pat in _SOURCE_PATTERNS:
        if re.search(pat, content, _FLAGS):
            found.append(name)
    return found


def extract_sinks(content: str) -> list[str]:
    """Return notable outbound sinks (deduped, capped)."""
    sinks: list[str] = []
    seen = set()
    for m in _URL_RE.finditer(content):
        url = m.group(0).rstrip('.,);')
        key = url[:120]
        if key in seen:
            continue
        seen.add(key)
        # Only surface URLs that look like real egress targets.
        if _PRIVATE_HOST_RE.match(url) or _PASTE_SINK_RE.search(url) \
                or url.startswith(("http://", "https://")):
            sinks.append(url)
        if len(sinks) >= 20:
            break
    return sinks


def has_private_network_sink(profile: CapabilityProfile) -> bool:
    return any(_PRIVATE_HOST_RE.match(s) for s in profile.sinks)


def has_paste_sink(profile: CapabilityProfile) -> bool:
    return any(_PASTE_SINK_RE.search(s) for s in profile.sinks)


def _read_all_text(directory: Path) -> str:
    return collect_text(directory)


def _skill_profile(skill_dir: Path) -> CapabilityProfile:
    content = _read_all_text(skill_dir)
    name = skill_dir.name
    skill_md = skill_dir / "SKILL.md"
    fp = str(skill_md) if skill_md.exists() else str(skill_dir)
    declared = _extract_declared_inputs(content)
    return CapabilityProfile(
        asset=f"skill:{name}",
        asset_type="skill",
        capabilities=extract_capabilities(content),
        sensitive_sources=extract_sensitive_sources(content),
        sinks=extract_sinks(content),
        declared_inputs=declared,
        trust_boundary="third_party_skill",
        file_path=fp,
    )


_INPUT_RE = re.compile(
    r'(?:input|param(?:eter)?|requires?|env|api[_-]?key|token|secret)'
    r'["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{2,40})',
    re.IGNORECASE,
)


def _extract_declared_inputs(content: str) -> list[str]:
    found = []
    seen = set()
    for m in _INPUT_RE.finditer(content):
        val = m.group(1)
        if val.lower() in seen:
            continue
        seen.add(val.lower())
        found.append(val)
        if len(found) >= 15:
            break
    return found


def _mcp_profiles(mcp_path: Path) -> list[CapabilityProfile]:
    """Build capability profiles from an MCP config file."""
    import json

    try:
        text = mcp_path.read_text(encoding="utf-8", errors="replace")
        text = re.sub(r'(?m)^\s*//.*$', '', text)
        text = re.sub(r',\s*([}\]])', r'\1', text)
        data = json.loads(text)
    except (json.JSONDecodeError, OSError):
        return []

    servers = data.get("mcpServers", data.get("servers", data))
    if not isinstance(servers, dict):
        return []

    profiles = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        blob = json.dumps(cfg)
        caps = extract_capabilities(blob)
        caps.add(MCP_TOOL_CALL)
        command = str(cfg.get("command", ""))
        args = " ".join(str(a) for a in cfg.get("args", []))
        url = str(cfg.get("url", ""))
        source = f"{command} {args} {url}"
        public = bool(re.search(
            r'clawhub|registry\.npmjs\.org|npx\s', source, re.IGNORECASE))
        profiles.append(CapabilityProfile(
            asset=f"mcp:{name}",
            asset_type="mcp_server",
            capabilities=caps,
            sensitive_sources=extract_sensitive_sources(blob),
            sinks=extract_sinks(blob + " " + url),
            declared_inputs=sorted(cfg.get("env", {}).keys())
            if isinstance(cfg.get("env"), dict) else [],
            trust_boundary="public_mcp" if public else "configured_mcp",
            file_path=str(mcp_path),
        ))
    return profiles


def build_profiles(ctx: ScanContext) -> list[CapabilityProfile]:
    """Build capability profiles for every discoverable asset in the context."""
    profiles: list[CapabilityProfile] = []
    seen_dirs = set()

    for skill_dir in ctx.skill_dirs:
        if skill_dir in seen_dirs:
            continue
        seen_dirs.add(skill_dir)
        profiles.append(_skill_profile(skill_dir))
    for sf in ctx.skill_files:
        if sf.parent not in seen_dirs:
            seen_dirs.add(sf.parent)
            profiles.append(_skill_profile(sf.parent))

    for mcp_path in ctx.mcp_config_files:
        profiles.extend(_mcp_profiles(mcp_path))

    return profiles
