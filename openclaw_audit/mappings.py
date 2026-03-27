"""Check definitions and framework mappings for all ~50 security checks."""

from .models import (
    Applicability,
    CheckDefinition,
    FixLevel,
    FrameworkMapping,
    Severity,
)

# ---------------------------------------------------------------------------
# Master registry of all checks
# ---------------------------------------------------------------------------

CHECKS: dict[str, CheckDefinition] = {}


def _reg(c: CheckDefinition) -> None:
    CHECKS[c.check_id] = c


# ── Configuration Audit (OC-CFG) ──────────────────────────────────────────

_reg(CheckDefinition(
    check_id="OC-CFG-001",
    title="Gateway authentication not configured",
    description="No authentication mode set for the Gateway WebSocket server. "
                "Any local process or website (ClawJacked) can control the agent.",
    category="Configuration",
    severity=Severity.CRITICAL,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI03"],
        atlas=["AML.T0040"],
        aicm=["IAM", "Application and Interface Security"],
        whitepaper_section="2.2",
    ),
    recommendation="Set gateway.auth.mode to 'token' with a minimum 32-character random value.",
    fix_level=FixLevel.MEDIUM,
))

_reg(CheckDefinition(
    check_id="OC-CFG-002",
    title="Gateway bound to all interfaces (0.0.0.0)",
    description="Gateway listens on all network interfaces, exposing the agent to "
                "the local network and potentially the internet.",
    category="Configuration",
    severity=Severity.CRITICAL,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05"],
        atlas=["AML.T0040"],
        aicm=["Infrastructure Security"],
        whitepaper_section="6.2",
    ),
    recommendation="Set gateway.bind to 'loopback' (127.0.0.1).",
    fix_level=FixLevel.MEDIUM,
))

_reg(CheckDefinition(
    check_id="OC-CFG-003",
    title="mDNS/Bonjour broadcasting enabled",
    description="OpenClaw broadcasts its presence via mDNS, leaking filesystem "
                "paths and metadata to devices on the local network.",
    category="Configuration",
    severity=Severity.MEDIUM,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI08"],
        aicm=["Infrastructure Security"],
        whitepaper_section="2.2",
    ),
    recommendation="Set discovery.mdns.mode to 'off' or OPENCLAW_DISABLE_BONJOUR=1.",
    fix_level=FixLevel.MEDIUM,
))

_reg(CheckDefinition(
    check_id="OC-CFG-004",
    title="Shell execution not restricted",
    description="tools.exec.security is not set to 'deny'. The agent may execute "
                "arbitrary shell commands, enabling prompt-injection-to-RCE.",
    category="Configuration",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05", "ASI01"],
        atlas=["AML.T0051.000", "AML.T0051.001"],
        aicm=["Application and Interface Security"],
        whitepaper_section="2.2",
    ),
    recommendation="Set tools.exec.security to 'deny' and tools.exec.ask to 'always'.",
    fix_level=FixLevel.MEDIUM,
))

_reg(CheckDefinition(
    check_id="OC-CFG-005",
    title="Tool approval not required",
    description="tools.exec.ask is not 'always'. The agent can invoke tools "
                "without user confirmation.",
    category="Configuration",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI02", "ASI09"],
        aicm=["Application and Interface Security"],
        whitepaper_section="2.2",
    ),
    recommendation="Set tools.exec.ask to 'always'.",
    fix_level=FixLevel.MEDIUM,
))

_reg(CheckDefinition(
    check_id="OC-CFG-006",
    title="Dangerous tool groups not denied",
    description="Control-plane tools (gateway, cron, sessions_spawn, sessions_send) "
                "or groups (automation, runtime, fs) are not explicitly denied.",
    category="Configuration",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI02", "ASI10"],
        atlas=["AML.T0081"],
        aicm=["Application and Interface Security"],
        whitepaper_section="2.2",
    ),
    recommendation="Add gateway, cron, sessions_spawn, sessions_send, "
                   "group:automation, group:runtime to tools.deny.",
    fix_level=FixLevel.MEDIUM,
))

_reg(CheckDefinition(
    check_id="OC-CFG-007",
    title="Sandbox mode disabled or insufficient",
    description="Agent sandbox is not set to 'all'. Code may execute directly on "
                "the host without containment.",
    category="Configuration",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05"],
        atlas=["AML.T0105"],
        aicm=["Infrastructure Security"],
        whitepaper_section="5.2",
    ),
    recommendation="Set sandbox.mode to 'all' for full Docker isolation.",
    fix_level=FixLevel.COMPLETE,
))

_reg(CheckDefinition(
    check_id="OC-CFG-008",
    title="Elevated tools enabled",
    description="tools.elevated.enabled is true. Elevated tools bypass sandbox "
                "restrictions and execute on the host.",
    category="Configuration",
    severity=Severity.MEDIUM,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI03", "ASI05"],
        atlas=["AML.T0105"],
        aicm=["Application and Interface Security"],
        whitepaper_section="5.2",
    ),
    recommendation="Set tools.elevated.enabled to false unless specific elevated "
                   "tools are required and individually approved.",
    fix_level=FixLevel.COMPLETE,
))

_reg(CheckDefinition(
    check_id="OC-CFG-009",
    title="DM policy set to 'open'",
    description="Direct message policy allows anyone to interact with the agent "
                "without authentication or pairing.",
    category="Configuration",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI01", "ASI03"],
        aicm=["IAM"],
        whitepaper_section="2.2",
    ),
    recommendation="Set dmPolicy to 'pairing' or 'allowlist'.",
    fix_level=FixLevel.MEDIUM,
))

_reg(CheckDefinition(
    check_id="OC-CFG-010",
    title="Session DM scope not isolated",
    description="session.dmScope is not 'per-channel-peer', allowing context "
                "leakage between different message senders.",
    category="Configuration",
    severity=Severity.MEDIUM,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI06", "ASI07"],
        aicm=["Data Security and Privacy Lifecycle Management"],
        whitepaper_section="2.2",
    ),
    recommendation="Set session.dmScope to 'per-channel-peer'.",
    fix_level=FixLevel.MEDIUM,
))

_reg(CheckDefinition(
    check_id="OC-CFG-011",
    title="Browser SSRF protection disabled",
    description="browser.ssrfPolicy.dangerouslyAllowPrivateNetwork is true or "
                "browser mode allows unrestricted navigation.",
    category="Configuration",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI02", "ASI05"],
        atlas=["AML.T0100"],
        aicm=["Application and Interface Security"],
        whitepaper_section="2.2",
    ),
    recommendation="Set dangerouslyAllowPrivateNetwork to false. Disable browser "
                   "if not required, or use hostnameAllowlist.",
    fix_level=FixLevel.MEDIUM,
))

_reg(CheckDefinition(
    check_id="OC-CFG-012",
    title="Workspace-only filesystem not enforced",
    description="tools.fs.workspaceOnly is not true. The agent has access to the "
                "entire user home directory.",
    category="Configuration",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI02", "ASI03"],
        atlas=["AML.T0085"],
        aicm=["Data Security and Privacy Lifecycle Management"],
        whitepaper_section="6.1",
    ),
    recommendation="Set tools.fs.workspaceOnly to true.",
    fix_level=FixLevel.MEDIUM,
))

_reg(CheckDefinition(
    check_id="OC-CFG-013",
    title="Container namespace join allowed",
    description="dangerouslyAllowContainerNamespaceJoin is true, allowing "
                "sandbox escape via container namespace access.",
    category="Configuration",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05"],
        atlas=["AML.T0105"],
        aicm=["Infrastructure Security"],
        whitepaper_section="5.2",
    ),
    recommendation="Set dangerouslyAllowContainerNamespaceJoin to false.",
    fix_level=FixLevel.MEDIUM,
))

# ── SOUL.md Integrity (OC-SOUL) ──────────────────────────────────────────

_reg(CheckDefinition(
    check_id="OC-SOUL-001",
    title="SOUL.md is writable",
    description="SOUL.md is writable by the agent's user, allowing prompt "
                "injection to establish persistent behavioral manipulation.",
    category="SOUL.md Integrity",
    severity=Severity.HIGH,
    applicability=Applicability.INSTANCE_ONLY,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI01", "ASI06"],
        atlas=["AML.T0081", "AML.T0080"],
        aicm=["Change Control and Configuration Management"],
        whitepaper_section="2.2",
    ),
    recommendation="Set SOUL.md to read-only (chmod 444) owned by admin.",
    fix_level=FixLevel.BASIC,
))

_reg(CheckDefinition(
    check_id="OC-SOUL-002",
    title="Base64-encoded content in SOUL.md",
    description="SOUL.md contains base64-encoded strings, a common technique "
                "for hiding payload instructions from human review.",
    category="SOUL.md Integrity",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI01", "ASI06"],
        atlas=["AML.T0080"],
        aicm=["Model Security"],
        whitepaper_section="2.2",
    ),
    recommendation="Remove base64-encoded content. Review decoded payload.",
))

_reg(CheckDefinition(
    check_id="OC-SOUL-003",
    title="Zero-width Unicode characters in SOUL.md",
    description="SOUL.md contains zero-width or invisible Unicode characters "
                "that can carry steganographic instructions invisible to reviewers.",
    category="SOUL.md Integrity",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI01", "ASI06"],
        atlas=["AML.T0080"],
        aicm=["Model Security"],
        whitepaper_section="2.2",
    ),
    recommendation="Strip all zero-width Unicode characters from SOUL.md.",
))

_reg(CheckDefinition(
    check_id="OC-SOUL-004",
    title="Embedded shell commands in SOUL.md",
    description="SOUL.md contains shell command patterns (curl, wget, bash, "
                "eval, exec, /bin/sh) that may indicate injection.",
    category="SOUL.md Integrity",
    severity=Severity.CRITICAL,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI01", "ASI05"],
        atlas=["AML.T0080", "AML.T0051.001"],
        aicm=["Model Security"],
        whitepaper_section="2.2",
    ),
    recommendation="Remove shell commands from SOUL.md. Investigate source.",
))

_reg(CheckDefinition(
    check_id="OC-SOUL-005",
    title="Suspicious instruction override patterns in SOUL.md",
    description="SOUL.md contains patterns like 'ignore previous instructions', "
                "'do not log', 'skip confirmation', or permission escalation language.",
    category="SOUL.md Integrity",
    severity=Severity.CRITICAL,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI01", "ASI10"],
        atlas=["AML.T0080", "AML.T0051.001"],
        aicm=["Model Security"],
        whitepaper_section="2.2",
    ),
    recommendation="Remove override instructions. Investigate how they were added.",
))

_reg(CheckDefinition(
    check_id="OC-SOUL-006",
    title="External URL references in SOUL.md",
    description="SOUL.md references external URLs that could serve as C2 "
                "endpoints or exfiltration targets.",
    category="SOUL.md Integrity",
    severity=Severity.MEDIUM,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI01", "ASI10"],
        atlas=["AML.T0080"],
        aicm=["Model Security"],
        whitepaper_section="2.2",
    ),
    recommendation="Review all URLs. Remove any that are not organizationally approved.",
))

_reg(CheckDefinition(
    check_id="OC-SOUL-007",
    title="HEARTBEAT.md writable or contains suspicious content",
    description="HEARTBEAT.md is writable or contains instructions that could "
                "establish a persistent C2 channel.",
    category="SOUL.md Integrity",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI06", "ASI10"],
        atlas=["AML.T0080", "AML.T0081"],
        aicm=["Change Control and Configuration Management"],
        whitepaper_section="2.2",
    ),
    recommendation="Lock HEARTBEAT.md to read-only. Review for injected instructions.",
    fix_level=FixLevel.BASIC,
))

# ── Skill Vetting (OC-SKILL) ─────────────────────────────────────────────

_reg(CheckDefinition(
    check_id="OC-SKILL-001",
    title="Prompt injection patterns in SKILL.md",
    description="Skill descriptor contains prompt injection indicators: hidden "
                "instructions, IMPORTANT tags, system prompt overrides.",
    category="Skill Vetting",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI01", "ASI04"],
        atlas=["AML.T0051.001", "AML.T0104"],
        aicm=["Supply Chain Management, Transparency and Accountability"],
        whitepaper_section="3.1",
    ),
    recommendation="Quarantine skill. Review SKILL.md content for hidden instructions.",
    fix_level=FixLevel.COMPLETE,
))

_reg(CheckDefinition(
    check_id="OC-SKILL-002",
    title="External download instructions in skill",
    description="Skill instructs users to download and run external software "
                "('Prerequisites' social engineering pattern from ClawHavoc).",
    category="Skill Vetting",
    severity=Severity.CRITICAL,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI04"],
        atlas=["AML.T0104"],
        aicm=["Supply Chain Management, Transparency and Accountability"],
        whitepaper_section="3.1",
    ),
    recommendation="Remove skill immediately. This matches the ClawHavoc attack pattern.",
    fix_level=FixLevel.COMPLETE,
))

_reg(CheckDefinition(
    check_id="OC-SKILL-003",
    title="Shell command execution in skill scripts",
    description="Skill contains scripts that execute shell commands, subprocess "
                "calls, or system() invocations.",
    category="Skill Vetting",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI04", "ASI05"],
        atlas=["AML.T0104"],
        aicm=["Supply Chain Management, Transparency and Accountability"],
        whitepaper_section="3.1",
    ),
    recommendation="Review all shell commands. Quarantine if not justified.",
    fix_level=FixLevel.COMPLETE,
))

_reg(CheckDefinition(
    check_id="OC-SKILL-004",
    title="Obfuscated code in skill",
    description="Skill contains obfuscated code: base64 decoding, hex encoding, "
                "eval(), exec(), or Unicode escape sequences.",
    category="Skill Vetting",
    severity=Severity.CRITICAL,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI04"],
        atlas=["AML.T0104"],
        aicm=["Supply Chain Management, Transparency and Accountability"],
        whitepaper_section="3.1",
    ),
    recommendation="Remove skill. Obfuscated code in skills is a strong malware indicator.",
    fix_level=FixLevel.COMPLETE,
))

_reg(CheckDefinition(
    check_id="OC-SKILL-005",
    title="Network exfiltration patterns in skill",
    description="Skill contains outbound network calls (curl, wget, fetch, "
                "requests.post) that could exfiltrate data.",
    category="Skill Vetting",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI04"],
        atlas=["AML.T0086", "AML.T0104"],
        aicm=["Supply Chain Management, Transparency and Accountability"],
        whitepaper_section="3.1",
    ),
    recommendation="Verify all network endpoints are legitimate and approved.",
))

_reg(CheckDefinition(
    check_id="OC-SKILL-006",
    title="Credential access patterns in skill",
    description="Skill references credential stores, SSH keys, keychains, "
                "browser profiles, or cryptocurrency wallets.",
    category="Skill Vetting",
    severity=Severity.CRITICAL,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI04"],
        atlas=["AML.T0082", "AML.T0083", "AML.T0104"],
        aicm=["Supply Chain Management, Transparency and Accountability"],
        whitepaper_section="3.1",
    ),
    recommendation="Remove skill immediately. Credential access is the primary "
                   "ClawHavoc/AMOS payload objective.",
    fix_level=FixLevel.COMPLETE,
))

# ── MCP Server Audit (OC-MCP) ────────────────────────────────────────────

_reg(CheckDefinition(
    check_id="OC-MCP-001",
    title="MCP server without authentication",
    description="An MCP server connection does not specify authentication.",
    category="MCP Server",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI07"],
        atlas=["AML.T0099"],
        aicm=["IAM", "Application and Interface Security"],
        whitepaper_section="4.4",
    ),
    recommendation="Configure authentication for all MCP server connections.",
))

_reg(CheckDefinition(
    check_id="OC-MCP-002",
    title="MCP server not version-pinned",
    description="MCP server uses 'latest' tag or no version pin, enabling "
                "rug-pull attacks via silent updates.",
    category="MCP Server",
    severity=Severity.MEDIUM,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI04"],
        atlas=["AML.T0099", "AML.T0104"],
        aicm=["Supply Chain Management, Transparency and Accountability"],
        whitepaper_section="4.2",
    ),
    recommendation="Pin MCP server versions to specific releases. Never use 'latest'.",
    fix_level=FixLevel.COMPLETE,
))

_reg(CheckDefinition(
    check_id="OC-MCP-003",
    title="Remote MCP server without TLS",
    description="An MCP server uses HTTP (not HTTPS) transport, allowing "
                "man-in-the-middle attacks.",
    category="MCP Server",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI07"],
        aicm=["Cryptography, Encryption and Key Management"],
        whitepaper_section="4.4",
    ),
    recommendation="Use HTTPS/TLS for all remote MCP server connections.",
))

_reg(CheckDefinition(
    check_id="OC-MCP-004",
    title="Hidden instructions in MCP tool descriptions",
    description="MCP tool descriptions contain hidden prompt injection "
                "payloads (IMPORTANT tags, system overrides, exfiltration instructions).",
    category="MCP Server",
    severity=Severity.CRITICAL,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI01", "ASI02"],
        atlas=["AML.T0099"],
        aicm=["Model Security"],
        whitepaper_section="4.3",
    ),
    recommendation="Remove MCP server. Tool poisoning is a critical attack vector.",
))

# ── File Permissions (OC-PERM) ────────────────────────────────────────────

_reg(CheckDefinition(
    check_id="OC-PERM-001",
    title="Config directory permissions too open",
    description="The OpenClaw config directory (~/.openclaw/) has permissions "
                "wider than 700, allowing other users to read agent data.",
    category="File Permissions",
    severity=Severity.MEDIUM,
    applicability=Applicability.INSTANCE_ONLY,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI03"],
        aicm=["Data Security and Privacy Lifecycle Management"],
        whitepaper_section="6.1",
    ),
    recommendation="Set config directory permissions to 700 (chmod 700).",
    fix_level=FixLevel.BASIC,
))

_reg(CheckDefinition(
    check_id="OC-PERM-002",
    title="Credential/config files permissions too open",
    description="Config files containing credentials have permissions wider "
                "than 600.",
    category="File Permissions",
    severity=Severity.HIGH,
    applicability=Applicability.INSTANCE_ONLY,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI03"],
        atlas=["AML.T0083"],
        aicm=["Data Security and Privacy Lifecycle Management"],
        whitepaper_section="6.1",
    ),
    recommendation="Set credential file permissions to 600 (chmod 600).",
    fix_level=FixLevel.BASIC,
))

# ── Network Exposure (OC-NET) ─────────────────────────────────────────────

_reg(CheckDefinition(
    check_id="OC-NET-001",
    title="Docker host network mode",
    description="Docker container uses host network mode, eliminating network "
                "isolation between the sandbox and the host.",
    category="Network Exposure",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05"],
        atlas=["AML.T0105"],
        aicm=["Infrastructure Security"],
        whitepaper_section="5.2",
    ),
    recommendation="Remove 'network: host'. Use a bridge network with explicit egress rules.",
    fix_level=FixLevel.COMPLETE,
))

# ── Credential Hygiene (OC-CRED) ─────────────────────────────────────────

_reg(CheckDefinition(
    check_id="OC-CRED-001",
    title="API keys in plaintext config files",
    description="Plaintext API keys or tokens found in configuration files.",
    category="Credential Hygiene",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI03"],
        atlas=["AML.T0083"],
        aicm=["Cryptography, Encryption and Key Management", "IAM"],
        whitepaper_section="7.2",
    ),
    recommendation="Move credentials to OS keychain or secrets manager. "
                   "Remove from config files.",
))

_reg(CheckDefinition(
    check_id="OC-CRED-002",
    title="API keys in .env files",
    description="Plaintext API keys found in .env files, accessible to any "
                "process running under the same user.",
    category="Credential Hygiene",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI03"],
        atlas=["AML.T0083"],
        aicm=["Cryptography, Encryption and Key Management"],
        whitepaper_section="7.2",
    ),
    recommendation="Migrate to secrets manager. Remove .env files with credentials.",
))

_reg(CheckDefinition(
    check_id="OC-CRED-003",
    title="Credentials in session transcripts",
    description="Session transcript files contain what appear to be API keys, "
                "tokens, or passwords captured during agent operation.",
    category="Credential Hygiene",
    severity=Severity.MEDIUM,
    applicability=Applicability.INSTANCE_ONLY,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI03"],
        atlas=["AML.T0085"],
        aicm=["Data Security and Privacy Lifecycle Management"],
        whitepaper_section="7.2",
    ),
    recommendation="Purge session transcripts containing credentials. "
                   "Implement output redaction.",
))

# ── Docker Sandbox Audit (OC-DOCK) ───────────────────────────────────────

_reg(CheckDefinition(
    check_id="OC-DOCK-001",
    title="No capability dropping configured",
    description="Docker configuration does not drop Linux capabilities. "
                "Containers run with default capability set.",
    category="Docker Sandbox",
    severity=Severity.MEDIUM,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05"],
        atlas=["AML.T0105"],
        aicm=["Infrastructure Security"],
        whitepaper_section="5.2",
    ),
    recommendation="Add cap_drop: ALL and selectively re-add only required capabilities.",
    fix_level=FixLevel.COMPLETE,
))

_reg(CheckDefinition(
    check_id="OC-DOCK-002",
    title="Root filesystem not read-only",
    description="Docker container root filesystem is not mounted read-only.",
    category="Docker Sandbox",
    severity=Severity.MEDIUM,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05"],
        atlas=["AML.T0105"],
        aicm=["Infrastructure Security"],
        whitepaper_section="5.2",
    ),
    recommendation="Set read_only: true and add explicit tmpfs/writable mounts.",
    fix_level=FixLevel.COMPLETE,
))

_reg(CheckDefinition(
    check_id="OC-DOCK-003",
    title="No seccomp profile configured",
    description="Docker configuration does not specify a seccomp profile for "
                "system call filtering.",
    category="Docker Sandbox",
    severity=Severity.MEDIUM,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05"],
        atlas=["AML.T0105"],
        aicm=["Infrastructure Security"],
        whitepaper_section="5.2",
    ),
    recommendation="Configure a custom seccomp profile restricting available syscalls.",
    fix_level=FixLevel.COMPLETE,
))

_reg(CheckDefinition(
    check_id="OC-DOCK-004",
    title="Dangerous bind mounts detected",
    description="Docker binds mount sensitive host paths: Docker socket, /etc, "
                "/proc, /sys, /dev, SSH directory, or browser profiles.",
    category="Docker Sandbox",
    severity=Severity.CRITICAL,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05", "ASI03"],
        atlas=["AML.T0105", "AML.T0083"],
        aicm=["Infrastructure Security"],
        whitepaper_section="5.2",
    ),
    recommendation="Remove dangerous bind mounts. Copy required files into container instead.",
))

_reg(CheckDefinition(
    check_id="OC-DOCK-005",
    title="Container runs as root",
    description="Docker container does not specify a non-root user.",
    category="Docker Sandbox",
    severity=Severity.MEDIUM,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05"],
        atlas=["AML.T0105"],
        aicm=["Infrastructure Security"],
        whitepaper_section="5.2",
    ),
    recommendation="Set user: to a non-root UID in the Docker configuration.",
    fix_level=FixLevel.COMPLETE,
))

_reg(CheckDefinition(
    check_id="OC-DOCK-006",
    title="Privileged container mode",
    description="Docker container runs in privileged mode, with full host access.",
    category="Docker Sandbox",
    severity=Severity.CRITICAL,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05"],
        atlas=["AML.T0105"],
        aicm=["Infrastructure Security"],
        whitepaper_section="5.2",
    ),
    recommendation="Remove privileged: true. Use specific capabilities instead.",
))

_reg(CheckDefinition(
    check_id="OC-DOCK-007",
    title="Seccomp or AppArmor profile set to unconfined",
    description="Security profile explicitly set to 'unconfined', disabling "
                "kernel-level containment.",
    category="Docker Sandbox",
    severity=Severity.HIGH,
    applicability=Applicability.BOTH,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI05"],
        atlas=["AML.T0105"],
        aicm=["Infrastructure Security"],
        whitepaper_section="5.2",
    ),
    recommendation="Remove 'unconfined' setting. Use default or custom profiles.",
    fix_level=FixLevel.COMPLETE,
))

# ── Version Check (OC-VER) ───────────────────────────────────────────────

_reg(CheckDefinition(
    check_id="OC-VER-001",
    title="OpenClaw version below minimum safe",
    description="Installed version is below v2026.2.26, which addresses all "
                "known critical CVEs through early March 2026.",
    category="Version",
    severity=Severity.CRITICAL,
    applicability=Applicability.INSTANCE_ONLY,
    frameworks=FrameworkMapping(
        owasp_asi=["ASI04"],
        aicm=["Threat and Vulnerability Management"],
        whitepaper_section="1.3",
    ),
    recommendation="Update to v2026.2.26 or later immediately.",
))

_reg(CheckDefinition(
    check_id="OC-VER-002",
    title="OpenClaw version not determinable",
    description="Could not determine the installed OpenClaw version from "
                "package.json or CLI output.",
    category="Version",
    severity=Severity.MEDIUM,
    applicability=Applicability.INSTANCE_ONLY,
    frameworks=FrameworkMapping(
        aicm=["Threat and Vulnerability Management"],
        whitepaper_section="1.3",
    ),
    recommendation="Verify installation integrity. Ensure OpenClaw is installed "
                   "from an official source.",
))


def get_check(check_id: str) -> CheckDefinition:
    return CHECKS[check_id]


def checks_for_context(applicability: Applicability) -> list[CheckDefinition]:
    """Return checks applicable to the given context type."""
    return [
        c for c in CHECKS.values()
        if c.applicability == Applicability.BOTH
        or c.applicability == applicability
    ]
