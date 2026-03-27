"""Skill vetting checks (OC-SKILL-001 through OC-SKILL-006)."""

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


# --- Injection patterns for SKILL.md ---
_INJECTION_PATTERNS = [
    (r'<IMPORTANT>', "IMPORTANT tag (tool poisoning)"),
    (r'<system>', "System prompt override tag"),
    (r'ignore\s+(?:all\s+)?previous', "Instruction override"),
    (r'you\s+must\s+(?:always|never)', "Behavioral mandate"),
    (r'do\s+not\s+(?:tell|inform|show)\s+the\s+user', "User deception"),
    (r'silently\s+', "Silent action directive"),
    (r'without\s+(?:the\s+)?user\s+(?:knowing|noticing)', "Covert action"),
    (r'forward\s+(?:all\s+)?(?:data|information|messages)\s+to', "Data forwarding"),
    (r'send\s+(?:all\s+)?(?:data|content|files)\s+to', "Data exfiltration"),
    (r'add\s+(?:a\s+)?(?:new\s+)?(?:rule|instruction)\s+to\s+(?:your|the)\s+(?:system|soul)',
     "Persistent injection"),
]

# --- Download/prerequisite patterns (ClawHavoc) ---
# These target the specific social engineering pattern where skills trick users
# into downloading and running external binaries, NOT legitimate install docs.
_DOWNLOAD_PATTERNS = [
    # Specific ClawHavoc pattern: "Prerequisites" section with a direct download URL
    (r'(?:prerequisites?|requirements?)\s*:?\s*\n.*(?:download\s+and\s+(?:run|install|execute)|'
     r'run\s+(?:this|the)\s+(?:following|below))',
     "Prerequisite with download-and-run instruction (ClawHavoc pattern)"),
    # Direct "download and run this binary/tool/script" instruction
    (r'(?:download|install)\s+(?:and\s+)?(?:run|execute)\s+(?:this|the)\s+'
     r'(?:tool|binary|script|executable|program|installer)',
     "External binary download-and-run instruction"),
    # Defanged URLs are always suspicious — legitimate docs don't use them
    (r'hxxps?://', "Defanged URL (malware indicator)"),
    # Vercel app URLs used as C2/payload hosting in ClawHavoc
    (r'openclawcli\.vercel\.app', "Known ClawHavoc payload URL"),
    # Base64 encoded shell commands in download instructions
    (r'(?:curl|wget)\s+.*\|\s*(?:bash|sh|python)', "Pipe-to-shell download pattern"),
]

# --- Shell execution patterns ---
_SHELL_PATTERNS = [
    (r'\bos\.system\s*\(', "os.system() call"),
    (r'\bsubprocess\.(run|call|Popen|check_output)\s*\(', "subprocess call"),
    (r'\bexec\s*\(', "exec() call"),
    (r'\beval\s*\(', "eval() call"),
    (r'child_process', "Node child_process"),
    (r'require\s*\(\s*["\']child_process', "require('child_process')"),
    (r'\bspawn\s*\(', "spawn() call"),
    (r'execSync\s*\(', "execSync() call"),
]

# --- Obfuscation patterns ---
_OBFUSCATION_PATTERNS = [
    (r'base64\.(?:b64decode|decodebytes)\s*\(', "base64 decode"),
    (r'atob\s*\(', "JavaScript atob()"),
    (r'Buffer\.from\s*\([^)]+,\s*["\']base64', "Node base64 decode"),
    (r'\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){5,}', "Hex-encoded string"),
    (r'\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){5,}', "Unicode escape sequence"),
    (r'String\.fromCharCode\s*\(', "String.fromCharCode()"),
    (r'chr\s*\(\s*\d+\s*\)', "chr() encoding"),
]

# --- Network exfiltration patterns ---
_NETWORK_PATTERNS = [
    (r'\bcurl\s+', "curl command"),
    (r'\bwget\s+', "wget command"),
    (r'requests\.(post|put|patch)\s*\(', "Python requests outbound"),
    (r'fetch\s*\(\s*["\']http', "fetch() outbound"),
    (r'XMLHttpRequest', "XMLHttpRequest"),
    (r'\.send\s*\(', "Socket/request send"),
    (r'axios\.(post|put|patch)\s*\(', "axios outbound"),
]

# --- Credential access patterns ---
_CREDENTIAL_PATTERNS = [
    (r'\.ssh/', "SSH directory access"),
    (r'id_rsa|id_ed25519|id_ecdsa', "SSH private key"),
    (r'\.gnupg', "GPG directory"),
    (r'Keychain|keychain', "macOS Keychain"),
    (r'\.aws/credentials', "AWS credentials"),
    (r'\.kube/config', "Kubernetes config"),
    (r'\.docker/config\.json', "Docker config"),
    (r'wallet\.dat|\.bitcoin|\.ethereum', "Crypto wallet"),
    (r'password[-_]?store', "Password store"),
    (r'Chrome.*(?:Login|Cookies)', "Browser credentials"),
    (r'Firefox.*(?:logins|cookies)', "Browser credentials"),
    (r'\.npmrc|\.pypirc', "Package registry tokens"),
]


def _scan_content(content: str, patterns: list[tuple[str, str]],
                  flags: int = re.IGNORECASE | re.MULTILINE) -> list[str]:
    """Return list of pattern descriptions that matched."""
    hits = []
    for pat, desc in patterns:
        if re.search(pat, content, flags):
            hits.append(desc)
    return hits


def _scan_skill(skill_dir: Path, findings: list[Finding]) -> None:
    """Scan a single skill directory."""
    # Collect all text content from the skill
    all_content = ""
    skill_md = skill_dir / "SKILL.md"
    fp = str(skill_md) if skill_md.exists() else str(skill_dir)

    for ext in ("*.md", "*.py", "*.js", "*.ts", "*.sh", "*.json", "*.yaml", "*.yml"):
        for f in skill_dir.rglob(ext):
            try:
                all_content += f.read_text(encoding="utf-8", errors="replace") + "\n"
            except OSError:
                pass

    if not all_content:
        return

    # OC-SKILL-001: Prompt injection
    injection_hits = _scan_content(all_content, _INJECTION_PATTERNS)
    if injection_hits:
        findings.append(_make("OC-SKILL-001", Status.FAIL,
            evidence=f"Injection patterns: {injection_hits}",
            file_path=fp))
    else:
        findings.append(_make("OC-SKILL-001", Status.PASS, file_path=fp))

    # OC-SKILL-002: External downloads
    download_hits = _scan_content(all_content, _DOWNLOAD_PATTERNS)
    if download_hits:
        findings.append(_make("OC-SKILL-002", Status.FAIL,
            evidence=f"Download patterns: {download_hits}",
            file_path=fp))
    else:
        findings.append(_make("OC-SKILL-002", Status.PASS, file_path=fp))

    # OC-SKILL-003: Shell execution
    shell_hits = _scan_content(all_content, _SHELL_PATTERNS)
    if shell_hits:
        findings.append(_make("OC-SKILL-003", Status.FAIL,
            evidence=f"Shell execution: {shell_hits}",
            file_path=fp))
    else:
        findings.append(_make("OC-SKILL-003", Status.PASS, file_path=fp))

    # OC-SKILL-004: Obfuscated code
    obfusc_hits = _scan_content(all_content, _OBFUSCATION_PATTERNS)
    if obfusc_hits:
        findings.append(_make("OC-SKILL-004", Status.FAIL,
            evidence=f"Obfuscation: {obfusc_hits}",
            file_path=fp))
    else:
        findings.append(_make("OC-SKILL-004", Status.PASS, file_path=fp))

    # OC-SKILL-005: Network exfiltration
    net_hits = _scan_content(all_content, _NETWORK_PATTERNS)
    if net_hits:
        findings.append(_make("OC-SKILL-005", Status.WARN,
            evidence=f"Network calls: {net_hits}",
            file_path=fp))
    else:
        findings.append(_make("OC-SKILL-005", Status.PASS, file_path=fp))

    # OC-SKILL-006: Credential access
    cred_hits = _scan_content(all_content, _CREDENTIAL_PATTERNS)
    if cred_hits:
        findings.append(_make("OC-SKILL-006", Status.FAIL,
            evidence=f"Credential access: {cred_hits}",
            file_path=fp))
    else:
        findings.append(_make("OC-SKILL-006", Status.PASS, file_path=fp))


def run(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    if not ctx.skill_dirs and not ctx.skill_files:
        for cid in [f"OC-SKILL-{i:03d}" for i in range(1, 7)]:
            findings.append(_make(cid, Status.SKIP,
                detail="No skills found"))
        return findings

    scanned = set()
    for skill_dir in ctx.skill_dirs:
        if skill_dir not in scanned:
            _scan_skill(skill_dir, findings)
            scanned.add(skill_dir)

    # Also scan lone SKILL.md files whose parent wasn't in skill_dirs
    for sf in ctx.skill_files:
        if sf.parent not in scanned:
            _scan_skill(sf.parent, findings)
            scanned.add(sf.parent)

    return findings
