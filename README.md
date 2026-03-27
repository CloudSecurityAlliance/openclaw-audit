# openclaw-audit

**OpenClaw Security Audit Tool — CSAI Hardening Guide Compliance Scanner**

A static analysis tool that scans OpenClaw installations and deployment repositories against the [CSAI "Hardening OpenClaw" whitepaper](https://cloudsecurityalliance.org), producing structured security gap reports with optional auto-remediation.

## Features

- **45 security checks** across 9 categories: Configuration, SOUL.md Integrity, Skill Vetting, MCP Server, File Permissions, Credentials, Docker Sandbox, Network Exposure, Version
- **Auto-detects** installed instances (`~/.openclaw/`), git repos (Docker Compose, NemoClaw), or hybrid environments
- **4 output formats**: terminal (colored), JSON, SARIF 2.1.0 (GitHub Advanced Security), Markdown
- **Auto-fix engine** with 3 levels: basic (permissions), medium (config hardening), complete (quarantine + Docker)
- **Framework mappings**: every finding tagged with OWASP ASI, MITRE ATLAS, CSA AICM, and whitepaper section
- **Zero external dependencies** — pure Python 3.10+ standard library

## Quick Start

```bash
# Install
pip install -e .

# Scan an OpenClaw installation
openclaw-audit ~/.openclaw/

# Scan a deployment repo
openclaw-audit ./my-openclaw-repo/

# Or run directly
python3 -m openclaw_audit ~/.openclaw/
```

## Usage

```
openclaw-audit [-h] [-f {terminal,json,sarif,markdown,all}] [-o OUTPUT]
               [--fix] [--fix-level {basic,medium,complete}]
               [--dry-run] [--quiet]
               target
```

### Examples

```bash
# Terminal report (default)
openclaw-audit ~/.openclaw/

# JSON output to file
openclaw-audit ~/.openclaw/ --format json -o report.json

# SARIF for CI/CD (GitHub Advanced Security)
openclaw-audit ./repo/ --format sarif -o results.sarif

# All formats at once
openclaw-audit ~/.openclaw/ --format all -o audit-report

# Preview what fixes would be applied
openclaw-audit ~/.openclaw/ --fix --dry-run

# Apply medium-level fixes (config hardening)
openclaw-audit ~/.openclaw/ --fix --fix-level medium

# Apply all fixes (includes skill quarantine + Docker hardening)
openclaw-audit ~/.openclaw/ --fix --fix-level complete
```

## Check Categories

| Category | Checks | What It Scans |
|----------|--------|---------------|
| Configuration | 13 | Gateway auth, binding, mDNS, shell exec, sandbox, SSRF, tool groups |
| SOUL.md Integrity | 7 | Base64 payloads, zero-width Unicode, shell commands, override patterns, C2 URLs |
| Skill Vetting | 6 | Prompt injection, ClawHavoc patterns, obfuscation, credential access, exfiltration |
| MCP Server | 4 | Authentication, version pinning, TLS, tool description poisoning |
| File Permissions | 2 | Config directory (700), credential files (600) |
| Credential Hygiene | 3 | API keys in configs, .env files, session transcripts |
| Docker Sandbox | 7 | cap_drop, read-only root, seccomp, dangerous mounts, privileged mode |
| Network Exposure | 1 | Docker host network mode |
| Version | 2 | Minimum safe version (v2026.2.26+) |

## Fix Levels

| Level | What It Does |
|-------|-------------|
| `basic` | File permissions (SOUL.md read-only, config 600, directory 700) |
| `medium` | All basic + config hardening (auth, loopback binding, mDNS off, exec deny, tool deny lists, SSRF off, workspace-only) |
| `complete` | All medium + quarantine suspicious skills, sandbox mode, elevated tools off, Docker hardening |

Fixes always create a `.bak` backup before modifying config files.

## Framework Mappings

Every finding includes mappings to:

- **OWASP Top 10 for Agentic Applications** (ASI01–ASI10)
- **MITRE ATLAS** agent techniques (AML.T0040–AML.T0105)
- **CSA AI Controls Matrix (AICM)** domains
- **CSAI Hardening Whitepaper** section references

## CI/CD Integration

### GitHub Actions

```yaml
- name: OpenClaw Security Audit
  run: |
    pip install openclaw-audit
    openclaw-audit ./openclaw-config/ --format sarif -o results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Exit Codes

- `0` — All checks passed (or only warnings)
- `1` — One or more checks failed

## License

Apache 2.0

## References

- [CSAI "Hardening OpenClaw" Whitepaper](https://cloudsecurityalliance.org)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
