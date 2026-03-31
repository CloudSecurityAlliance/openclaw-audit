# openclaw-audit

**OpenClaw Security Audit Tool — CSAI Hardening Guide Compliance Scanner**

A static analysis tool that scans OpenClaw installations and deployment repositories against the [CSAI "Hardening OpenClaw" whitepaper](https://cloudsecurityalliance.org), producing structured security gap reports with optional auto-remediation.

## Features

- **53 security checks** across 9 categories: Configuration, SOUL.md Integrity, Skill Vetting, MCP Server, File Permissions, Credentials, Docker Sandbox, Network Exposure, Version
- **Auto-detects** installed instances (`~/.openclaw/`), git repos (Docker Compose, NemoClaw), or hybrid environments
- **Remote SSH scanning** of individual hosts or entire fleets via `--hosts`
- **4 output formats**: terminal (colored), JSON, SARIF 2.1.0 (GitHub Advanced Security), Markdown
- **Auto-fix engine** with 3 levels: basic (permissions), medium (config hardening), complete (quarantine + Docker) — fixes are pushed back to remote hosts automatically
- **Framework mappings**: every finding tagged with OWASP ASI, MITRE ATLAS, MAESTRO, CSA AICM, and whitepaper section
- **Framework coverage reports**: OWASP Agentic Top 10, MAESTRO layer, and Phase 0 emergency checklist tables in markdown output
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
               [--hosts HOSTS_FILE] [--ssh-key KEY] [--password]
               [target]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `target` | Local path or remote target (`user@host:/path`). Omit if using `--hosts`. |

### Options

| Flag | Description |
|------|-------------|
| `-f`, `--format` | Output format: `terminal` (default), `json`, `sarif`, `markdown`, `all` |
| `-o`, `--output` | Output file path. With `--hosts`, this is a directory for per-host reports. |
| `--fix` | Apply auto-fixes. Fixes are pushed back to remote hosts via SSH. |
| `--fix-level` | Fix aggressiveness: `basic`, `medium`, `complete` (default) |
| `--dry-run` | Show what fixes would be applied without making changes |
| `-q`, `--quiet` | Suppress terminal output |
| `--hosts` | File with one target per line for fleet scanning |
| `--ssh-key` | Path to SSH private key for remote connections |
| `-p`, `--password` | Prompt for SSH password. With `--hosts`, prompts once and reuses for all hosts. |

### Examples

```bash
# Terminal report (default)
openclaw-audit ~/.openclaw/

# JSON output to file
openclaw-audit ~/.openclaw/ --format json -o report.json

# SARIF for CI/CD (GitHub Advanced Security)
openclaw-audit ./repo/ --format sarif -o results.sarif

# Markdown report with framework coverage tables
openclaw-audit ~/.openclaw/ --format markdown -o report.md

# All formats at once
openclaw-audit ~/.openclaw/ --format all -o audit-report

# Preview what fixes would be applied
openclaw-audit ~/.openclaw/ --fix --dry-run

# Apply medium-level fixes (config hardening)
openclaw-audit ~/.openclaw/ --fix --fix-level medium

# Apply all fixes (includes skill quarantine + Docker hardening)
openclaw-audit ~/.openclaw/ --fix --fix-level complete
```

## Remote SSH Scanning

Scan remote OpenClaw installations over SSH without installing anything on the target host. Files are fetched via SSH+tar, scanned locally, and fixes (if applied) are pushed back.

```bash
# Scan a remote host (SSH key from agent or ~/.ssh/)
openclaw-audit root@server.example.com:/home/openclaw/

# Specify SSH key
openclaw-audit deploy@10.0.1.50:/opt/openclaw --ssh-key ~/.ssh/deploy_key

# Use password authentication
openclaw-audit admin@host.internal:/home/openclaw -p

# Remote scan with auto-fix (fixes pushed back via SSH)
openclaw-audit root@server:/home/openclaw --fix --fix-level medium
```

### Fleet Mode

Scan multiple hosts from a file. Each line is a target in `user@host:/path` format (lines starting with `#` are ignored).

```bash
# hosts.txt
root@prod-1.example.com:/home/openclaw
root@prod-2.example.com:/home/openclaw
deploy@staging:/opt/openclaw

# Scan all hosts, save per-host reports to a directory
openclaw-audit --hosts hosts.txt --format markdown -o reports/

# Fleet scan with password auth (prompts once, reuses for all)
openclaw-audit --hosts hosts.txt -p

# Fleet scan with fixes
openclaw-audit --hosts hosts.txt --fix --dry-run
```

Hostnames without a path default to `root@host:/home/openclaw`.

## Check Categories

| Category | Checks | What It Scans |
|----------|--------|---------------|
| Configuration | 18 | Gateway auth, binding, mDNS, shell exec, sandbox, SSRF, tool groups, auto-update, Moltbook heartbeat, token strength, config.patch, sensitive dirs |
| SOUL.md Integrity | 7 | Base64 payloads, zero-width Unicode, shell commands, override patterns, C2 URLs |
| Skill Vetting | 6 | Prompt injection, ClawHavoc patterns, obfuscation, credential access, exfiltration |
| MCP Server | 5 | Authentication, version pinning, TLS, tool description poisoning, public source detection |
| File Permissions | 2 | Config directory (700), credential files (600) |
| Credential Hygiene | 4 | API keys in configs, .env files, session transcripts, standing long-lived keys |
| Docker Sandbox | 7 | cap_drop, read-only root, seccomp, dangerous mounts, privileged mode |
| Network Exposure | 2 | Docker host network mode, egress restrictions |
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
- **MAESTRO** agentic AI security layers (L1–L7)
- **CSA AI Controls Matrix (AICM)** domains
- **CSAI Hardening Whitepaper** section references

The markdown report includes coverage summary tables for OWASP Agentic Top 10, MAESTRO layers, and Phase 0 emergency checklist alignment.

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
- [MAESTRO Framework](https://cloudsecurityalliance.org/artifacts/maestro-multi-agent-security-framework)
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
