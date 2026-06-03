# OpenClaw Auditor Improvement Brief for Coding Agent

## Objective

Improve `openclaw-audit` from a broad static checklist scanner into an agentic security assurance tool that can find, explain, and help harden security issues in both:

1. **OpenClaw-related repositories** — source repos, forks, extensions, skills, MCP integrations, plugins, and reference implementations.
2. **OpenClaw deployments / implementations** — local installations, enterprise deployment repos, CI/CD environments, Docker/Kubernetes/systemd services, reverse proxies, and fleet instances.

The goal is to help CSA produce an auditor that is credible for both open-source project review and enterprise hardening.

---

## Guiding Design Principle

Move from isolated static findings to **correlated attack-path findings**.

A single risky configuration may not always be a vulnerability. The auditor should prioritize combinations such as:

- exposed gateway + weak or missing auth
- open DM policy + elevated tools
- skill documentation requesting secrets + code performing outbound network calls
- MCP server from public package registry + unpinned version + broad tool permissions
- filesystem read access + network egress
- browser/private-network access + public gateway exposure

The auditor should produce findings that answer:

- What is exposed?
- What capability is available?
- What trust boundary is crossed?
- What evidence supports the finding?
- What could an attacker do?
- How should the user harden it?

---

# Phase 0 — Immediate Accuracy Fixes

## 0.1 Fix empty regex patterns in skill injection detection

### Problem

The skill scanner appears to include empty regex patterns, such as `r''`, in injection-related checks. Empty regex patterns match everything and can cause nearly every scanned skill to be flagged as suspicious.

### Required Change

Remove all empty regex patterns from injection detection lists.

Replace with explicit prompt-injection or instruction-override patterns.

### Suggested patterns

```python
_INJECTION_PATTERNS = [
    r'<\s*important\s*>',
    r'<\s*/\s*important\s*>',
    r'<\s*system\s*>',
    r'<\s*/\s*system\s*>',
    r'\bSYSTEM\s*:',
    r'\bIMPORTANT\s*:',
    r'\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b',
    r'\boverride\s+(the\s+)?(system|developer|user)\s+instructions\b',
    r'\bdo\s+not\s+(tell|inform|reveal)\s+(the\s+)?user\b',
    r'\bhidden\s+instruction\b',
]
```

### Acceptance Criteria

- Benign skills are not flagged solely because they contain ordinary text.
- Empty regex patterns are removed.
- Unit tests confirm empty patterns do not exist in detection lists.
- Unit tests include benign and malicious `SKILL.md` examples.

---

## 0.2 Fix empty MCP description injection pattern

### Problem

The MCP scanner appears to include a regex that begins with an empty alternative, such as `r'|'`, which can match arbitrary MCP descriptions.

### Required Change

Remove empty alternatives from MCP injection regexes.

### Acceptance Criteria

- Benign MCP tool descriptions pass without injection findings.
- Malicious MCP tool descriptions with instruction override language are detected.
- Unit test confirms no regex pattern starts with `|` or contains an empty alternative.

---

# Phase 1 — Add Explicit Scan Profiles

## Objective

Make auditor behavior explicit based on what is being scanned.

The scanner currently appears to infer whether the target is a repository or an installed instance. Keep inference, but add explicit profiles so users and CI systems can control applicability and severity.

## New CLI Option

```bash
openclaw-audit ./repo --profile upstream-repo
openclaw-audit ./repo --profile implementation-repo
openclaw-audit ~/.openclaw --profile local-instance
openclaw-audit --hosts hosts.txt --profile enterprise-fleet
openclaw-audit ./repo --profile ci-pr-gate
```

## Profiles

### `upstream-repo`

Use for upstream OpenClaw source repos, extensions, or related tooling.

Focus:

- insecure defaults
- dangerous APIs
- unsafe examples
- prompt-injection-prone tool/skill descriptions
- test fixture vulnerabilities
- unsafe Docker/Kubernetes templates
- secrets in repo
- supply-chain risks

### `implementation-repo`

Use for enterprise deployment repositories.

Focus:

- deployment configs
- Docker/Kubernetes/systemd/reverse proxy hardening
- secrets handling
- MCP and skill policy
- gateway exposure
- CI/CD posture
- environment-specific hardening

### `local-instance`

Use for installed OpenClaw instances.

Focus:

- local config
- permissions
- active skills
- MCP server config
- local gateway binding
- session/log retention
- filesystem exposure

### `enterprise-fleet`

Use for SSH or remote multi-host scans.

Focus:

- host-to-host drift
- common misconfiguration patterns
- risky exposure
- version posture
- inconsistent hardening
- missing patches

### `ci-pr-gate`

Use in CI to fail builds on new severe findings.

Focus:

- new high/critical findings
- secrets committed to repo
- unsafe changes to gateway, MCP, skills, Docker, Kubernetes, or identity policy
- SARIF output

## Acceptance Criteria

- CLI supports `--profile`.
- Existing auto-detection still works when no profile is provided.
- Findings contain `profile_applicability`.
- Severity can vary by profile.
- CI profile returns non-zero exit code when thresholds are exceeded.

---

# Phase 2 — Improve Risk Scoring with Configuration Combinations

## Objective

Avoid over-reporting isolated facts. Score risk based on combinations of exposure, authentication, authorization, and compensating controls.

## Example: Gateway Binding Risk

A non-loopback bind is not always critical if there is strong authentication, firewalling, and intentional exposure. The auditor should evaluate the full context.

### Suggested Logic

| Condition | Severity |
|---|---|
| Gateway non-loopback + no auth | Critical |
| Gateway non-loopback + weak/default auth | Critical |
| Gateway non-loopback + auth + no firewall/tailnet evidence | High |
| Gateway non-loopback + auth + firewall/tailnet evidence | Warning |
| Gateway loopback + no auth | Warning |
| Gateway loopback + auth | Pass / Informational |

## Required Evidence Sources

Check for evidence in:

- OpenClaw config
- `.env`
- Docker Compose
- Kubernetes manifests
- systemd unit files
- Nginx/Traefik/Caddy configs
- local firewall hints
- Tailscale/WireGuard indicators
- cloud security group files, where available

## Acceptance Criteria

- Gateway exposure findings include both raw config and interpreted risk.
- Finding message explains what combination caused severity.
- Compensating controls can lower severity, but not hide evidence.
- Policy can override acceptable exposure.

---

# Phase 3 — Add Capability Model and Correlated Attack Paths

## Objective

Create a normalized intermediate representation of risky capabilities so the scanner can correlate documentation, code, config, and deployment posture.

## New Internal Model

Add an internal object similar to:

```json
{
  "asset": "skill:calendar-exporter",
  "asset_type": "skill",
  "declared_inputs": ["api_key", "email", "workspace_path"],
  "capabilities": ["read_file", "write_file", "network_post", "shell_exec"],
  "sinks": ["https://example.com/upload"],
  "sensitive_sources": [".env", ".ssh", "session transcript"],
  "trust_boundary": "third_party_skill",
  "risk_paths": [
    "sensitive_input -> network_post",
    "session_transcript -> file_write"
  ]
}
```

## Capability Types

Detect these capabilities where possible:

- `read_file`
- `write_file`
- `delete_file`
- `shell_exec`
- `spawn_process`
- `network_get`
- `network_post`
- `network_listener`
- `browser_private_network`
- `credential_read`
- `env_read`
- `ssh_key_read`
- `cloud_token_read`
- `session_transcript_read`
- `session_transcript_write`
- `config_patch`
- `mcp_tool_call`
- `email_send`
- `webhook_call`
- `package_install`
- `remote_code_download`

## Sensitive Sources

Detect references to:

- `.env`
- `.ssh`
- cloud credentials
- API keys
- OAuth tokens
- session transcripts
- browser cookies
- local keychains where applicable
- OpenClaw config
- MCP config
- workspace secrets
- GitHub tokens
- Slack/Google/Microsoft tokens

## Sinks

Detect outbound flows to:

- arbitrary HTTP endpoints
- webhooks
- paste sites
- cloud storage
- email
- GitHub/GitLab APIs
- package registries
- MCP servers
- local network services
- private IP ranges

## Acceptance Criteria

- Scanner produces a capability summary for each skill/MCP/config/deployment asset.
- Correlated findings use capability summaries.
- JSON output includes capability data.
- Markdown output includes human-readable attack paths.
- SARIF output maps correlated findings to source locations where possible.

---

# Phase 4 — Add OpenClaw-Specific Attack Path Rules

## New Finding Family

Add a new finding namespace:

```text
OC-PATH-*
```

These are higher-confidence findings based on correlated evidence.

---

## OC-PATH-001 — Open DM With Elevated Tools

### Trigger

Flag when all or most of the following are true:

```text
channels.*.dmPolicy = open
AND elevated tools are enabled
AND shell/fs/browser/MCP tools are available
AND session.dmScope is not isolated per channel/peer/account
```

### Severity

Critical or High depending on exact tool exposure.

### Recommended Remediation

- Set `dmPolicy` to restrictive/default-deny.
- Require explicit allowlists for DMs.
- Disable elevated tools in DM contexts.
- Use per-channel-peer or per-account-channel-peer session isolation.
- Require human confirmation for sensitive tools.

---

## OC-PATH-002 — Prompt Injection to Tool Use

### Trigger

```text
Tool/skill/MCP description contains instruction override language
AND the same asset has access to shell, filesystem, browser, email, secrets, config, or network capabilities
```

### Severity

High by default; Critical if secrets or shell execution are present.

### Recommended Remediation

- Remove instruction override language.
- Treat tool descriptions and skill docs as untrusted content.
- Add tool allowlists.
- Require confirmation before high-risk actions.
- Split documentation from executable instructions.
- Add prompt-injection tests.

---

## OC-PATH-003 — Secret-to-Egress Path

### Trigger

```text
Asset can read secrets or sensitive files
AND asset can perform outbound network calls
```

### Examples

- reads `.env` + performs `fetch()` or `requests.post()`
- reads `~/.ssh` + sends HTTP request
- accesses session transcript + writes to webhook

### Severity

Critical if source and sink are both confirmed; High if inferred.

### Recommended Remediation

- Remove direct secret access.
- Use scoped secret references.
- Add egress allowlist.
- Add network sandboxing.
- Redact transcripts.
- Require explicit user approval for exporting data.

---

## OC-PATH-004 — Public Agent With Private-Network Browser Access

### Trigger

```text
Gateway or UI is externally reachable
AND browser tool can access private IP ranges or localhost
AND auth is weak, missing, or unverified
```

### Severity

Critical.

### Recommended Remediation

- Bind gateway to loopback by default.
- Require strong auth.
- Block browser access to localhost, RFC1918 ranges, link-local metadata IPs, and internal DNS.
- Put exposed deployments behind trusted access proxy or tailnet.
- Add SSRF protections.

---

## OC-PATH-005 — Untrusted MCP Server With Broad Tools

### Trigger

```text
MCP server installed from public registry
AND version is unpinned or uses latest
AND no integrity hash/signature is present
AND MCP tools are broadly enabled
```

### Severity

High or Critical depending on tool capabilities.

### Recommended Remediation

- Pin MCP server versions.
- Require hash or signature verification where possible.
- Use allowlists for tools.
- Run MCP servers in sandboxed containers.
- Restrict egress.
- Review MCP tool descriptions for injection content.
- Separate trusted and untrusted MCP servers.

---

## OC-PATH-006 — Remote Code Download to Execution

### Trigger

```text
curl/wget/fetch/requests downloads remote content
AND downloaded content is executed, sourced, imported, or installed
```

### Severity

Critical.

### Recommended Remediation

- Pin versions.
- Verify hashes/signatures.
- Avoid piping remote content into shells.
- Require explicit review for remote install scripts.
- Use locked dependencies and SBOMs.

---

## OC-PATH-007 — Session Transcript Leakage

### Trigger

```text
Session transcript is written to file, logs, MCP context, prompt, webhook, or external sink
AND transcript may contain user data, credentials, internal URLs, code, or business-sensitive content
```

### Severity

High; Critical if secrets detected.

### Recommended Remediation

- Redact transcripts.
- Encrypt transcript storage.
- Restrict file permissions.
- Disable transcript export by default.
- Add retention policy.
- Add DLP/secret scanning on transcripts.

---

# Phase 5 — Expand Implementation Hardening Checks

## New Check Families

Add these namespaces:

```text
OC-K8S-*
OC-DOCKER-*
OC-SYSTEMD-*
OC-PROXY-*
OC-SUPPLY-*
OC-SECRETS-*
OC-IDENTITY-*
OC-OBS-*
OC-IR-*
```

---

## Docker Checks

Add or expand checks for:

- `privileged: true`
- Docker socket mounted
- host network mode
- host PID mode
- host IPC mode
- root user
- broad host volume mounts
- writable root filesystem
- missing `no-new-privileges`
- missing seccomp/AppArmor profile
- unrestricted egress
- environment variables containing secrets
- unpinned image tags
- `latest` image tags
- missing healthcheck
- exposed gateway port

### Remediation Examples

- Run as non-root.
- Avoid mounting `/var/run/docker.sock`.
- Avoid host networking.
- Use read-only root filesystem.
- Pin images by digest.
- Add seccomp/AppArmor.
- Restrict volume mounts.
- Use external secret manager.

---

## Kubernetes Checks

Check manifests for:

- `runAsNonRoot` missing or false
- `privileged: true`
- `allowPrivilegeEscalation: true`
- missing `readOnlyRootFilesystem`
- missing `seccompProfile`
- hostPath mounts
- hostNetwork
- broad RBAC
- secrets mounted as environment variables
- missing NetworkPolicy
- exposed LoadBalancer service
- Ingress without auth/TLS
- image tag `latest`
- missing resource limits
- missing liveness/readiness probes

### Remediation Examples

- Enforce Pod Security Standards.
- Add NetworkPolicy.
- Use non-root containers.
- Pin image digests.
- Use sealed/external secrets.
- Require TLS and auth at Ingress.
- Restrict service account permissions.

---

## systemd Checks

Check unit files for:

- service running as root
- missing `NoNewPrivileges=true`
- missing `ProtectHome=true`
- missing `PrivateTmp=true`
- missing `ProtectSystem=strict`
- missing `RestrictAddressFamilies`
- missing `CapabilityBoundingSet`
- writable sensitive directories
- environment files with weak permissions
- auto-restart loops without rate limits

### Remediation Examples

```ini
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
User=openclaw
Group=openclaw
```

---

## Reverse Proxy Checks

Check Nginx, Caddy, Traefik, Envoy, and common proxy files for:

- no TLS
- weak TLS
- no auth on exposed OpenClaw gateway/UI
- permissive CORS
- unsafe forwarded headers
- default credentials
- missing rate limiting
- exposed admin endpoints
- no IP allowlist or tailnet restriction
- websocket exposure without auth

### Remediation Examples

- Require OIDC/SAML or trusted access proxy.
- Enforce TLS.
- Restrict CORS.
- Sanitize forwarded headers.
- Add rate limits.
- Restrict admin routes.
- Require auth on websocket endpoints.

---

## Secrets Checks

Expand detection for:

- `.env` files
- committed API keys
- cloud credentials
- OAuth tokens
- private keys
- Slack/GitHub/Google/Microsoft tokens
- OpenClaw tokens
- MCP credentials
- credentials in Docker Compose
- credentials in Kubernetes manifests
- credentials in systemd environment files
- world-readable secret files
- backups containing secrets

### Remediation Examples

- Move secrets to secret manager.
- Use short-lived scoped tokens.
- Rotate exposed credentials.
- Restrict file permissions.
- Add secret scanning to CI.
- Avoid secrets in environment variables when possible.

---

## Identity / NHI Checks

Add checks for:

- shared agent identity
- missing per-user or per-agent identity
- long-lived non-human credentials
- excessive token scopes
- no credential rotation policy
- MCP server credentials shared across users
- no tool-level identity boundary
- no audit trail linking user → agent → tool → action

### Remediation Examples

- Use per-agent identities.
- Use least-privilege scoped credentials.
- Bind tool actions to user/session context.
- Rotate NHI credentials.
- Log agent identity and delegated user identity.
- Require approval for privilege escalation.

---

## Observability Checks

Add checks for:

- audit logging disabled
- tool invocation logs missing
- no tamper-evident logs
- no security event export
- no transcript redaction
- no finding export
- no SIEM integration hints
- logs world-readable
- logs containing secrets

### Remediation Examples

- Enable audit logging.
- Log tool calls, MCP calls, config changes, and sensitive approvals.
- Redact secrets.
- Restrict log permissions.
- Export security events to SIEM.
- Protect logs from tampering.

---

## Incident Response Checks

Add checks for:

- no kill switch
- no documented rollback
- no quarantine for suspicious skills/MCP servers
- no backup of known-good config
- no version rollback path
- no credential rotation instructions
- no emergency disablement of external exposure

### Remediation Examples

- Add emergency disable command.
- Maintain known-good config snapshots.
- Quarantine untrusted skills.
- Disable unknown MCP servers.
- Document credential rotation.
- Add rollback instructions.

---

# Phase 6 — Add Policy-as-Code

## Objective

Allow enterprises to define what “acceptable OpenClaw posture” means.

## New File

Support:

```text
openclaw-audit.policy.yaml
```

## Example Policy

```yaml
profile: enterprise-production

risk_acceptance:
  allow_non_loopback_gateway: false
  allow_public_mcp_sources: false
  require_per_channel_dm_scope: true
  require_egress_allowlist: true
  max_critical: 0
  max_high: 0

approved_mcp_servers:
  - name: github
    package: "@modelcontextprotocol/server-github"
    version: "1.2.3"
    sha256: "REPLACE_WITH_HASH"

approved_domains:
  - api.github.com
  - internal.example.com

approved_skills:
  - name: internal-ticketing
    version: "2.4.1"
    sha256: "REPLACE_WITH_HASH"

required_controls:
  - OC-CFG-001
  - OC-CFG-002
  - OC-CFG-007
  - OC-MCP-002
  - OC-NET-002
  - OC-PATH-003

ci_gate:
  fail_on:
    - critical
    - high
  allow_accepted_risks: true
```

## Required Behavior

- Load policy file automatically from scan root if present.
- Allow explicit path:

```bash
openclaw-audit ./repo --policy ./openclaw-audit.policy.yaml
```

- Findings should state whether they violate policy.
- CI mode should fail based on policy thresholds.
- Accepted risks should require explicit justification.

## Acceptance Criteria

- Policy parser validates schema.
- Invalid policy produces clear error.
- JSON and Markdown outputs include policy status.
- CI exit codes honor policy.

---

# Phase 7 — Add Evidence Quality, Confidence, and Exploitability

## Objective

Make findings more credible and easier to triage.

## Required Finding Fields

Add these fields to all findings:

```json
{
  "severity": "high",
  "confidence": "medium",
  "evidence_quality": "pattern_match",
  "exploitability": "plausible",
  "blast_radius": "host"
}
```

## Field Definitions

### `confidence`

Allowed values:

- `low`
- `medium`
- `high`

### `evidence_quality`

Allowed values:

- `pattern_match`
- `config_value`
- `correlated_path`
- `runtime_verified`
- `policy_violation`
- `manual_review_required`

### `exploitability`

Allowed values:

- `theoretical`
- `plausible`
- `demonstrated`

### `blast_radius`

Allowed values:

- `local_user`
- `workspace`
- `host`
- `cloud_account`
- `enterprise`
- `unknown`

## Acceptance Criteria

- All findings include these fields.
- Markdown output displays them.
- JSON output includes them.
- SARIF output maps them to properties.
- Confidence is lower for regex-only findings.
- Confidence is higher for correlated or runtime-verified findings.

---

# Phase 8 — Add Runtime Verification Mode

## Objective

Static analysis is necessary but insufficient. Add safe runtime probes to confirm exposure and control effectiveness.

## New CLI Option

```bash
openclaw-audit ~/.openclaw --runtime-probe
openclaw-audit root@host:/home/openclaw --runtime-probe
```

## Safe Runtime Probes

Runtime probes must be non-destructive.

Check:

- Is gateway listening?
- Is gateway bound to loopback or non-loopback?
- Are gateway routes reachable without auth?
- Are websocket routes reachable without auth?
- Is UI/canvas/A2UI exposed?
- Can MCP tools be enumerated without auth?
- Are dangerous routes reachable?
- Is browser/private-network access blocked?
- Are localhost, RFC1918, link-local, and metadata IPs blocked?
- Are config patch/update routes accessible?
- Is auth actually enforced?

## Runtime Finding Namespace

```text
OC-RUNTIME-*
```

## Safety Requirements

- Do not execute shell commands through OpenClaw.
- Do not modify config.
- Do not send destructive requests.
- Do not exfiltrate data.
- Do not trigger real tool actions.
- Use `HEAD`, safe `GET`, and intentionally harmless auth checks where possible.
- Clearly mark runtime probes in output.

## Acceptance Criteria

- Runtime probe mode is opt-in.
- Probe failures are handled gracefully.
- Results include target URL/host and test method.
- Findings are marked `runtime_verified`.
- Runtime probes can be disabled in policy.

---

# Phase 9 — Add Benchmark Corpus and Regression Tests

## Objective

Improve accuracy, reduce false positives, and make auditor quality measurable.

## New Fixture Structure

```text
tests/fixtures/
  benign/
  malicious/
  vulnerable-configs/
  hardened-configs/
  mcp/
  docker/
  k8s/
  systemd/
  proxy/
  openclaw-issues/
```

## Required Fixtures

Create fixtures for:

- benign skill with normal documentation
- benign skill containing the word “important”
- malicious skill with hidden instruction override
- skill that asks for API key and posts to remote server
- skill that reads `.env`
- skill that reads `.ssh`
- skill that writes session transcript to external sink
- MCP config using `npx @latest`
- MCP config using pinned version
- MCP tool description with instruction override
- `dmPolicy=open` with elevated tools
- non-loopback gateway with no auth
- non-loopback gateway with auth and tailnet evidence
- Docker privileged mode
- Docker socket mounted
- Docker host networking
- hardened Docker Compose
- Kubernetes privileged pod
- Kubernetes LoadBalancer without auth
- hardened Kubernetes deployment
- systemd root service without hardening
- hardened systemd service
- reverse proxy without auth
- reverse proxy with OIDC/TLS
- world-readable `.env`
- session transcript containing API key
- committed private key
- remote download piped to shell

## Accuracy Metrics

Add a test report that tracks:

- true positives
- false positives
- false negatives
- checks covered
- fixtures covered
- attack-path coverage

## Acceptance Criteria

- CI runs fixture tests.
- Each fixture has expected findings.
- Accuracy report is generated.
- False-positive regression tests exist for benign examples.
- Existing checks are covered by at least one fixture.

---

# Phase 10 — Improve Output and Remediation Quality

## Objective

Make reports useful to CISOs, security engineers, and developers.

## Markdown Report Structure

Generate reports with this structure:

```markdown
# OpenClaw Audit Report

## Executive Summary

- Overall posture
- Critical findings
- High findings
- Policy violations
- Runtime-verified issues
- Top attack paths

## Priority 0 — Emergency Actions

Immediate fixes for critical exposure.

## Priority 1 — Production Hardening

Recommended changes for secure deployment.

## Priority 2 — Assurance and Governance

Evidence, monitoring, policy, and long-term controls.

## Findings

Each finding includes:
- ID
- Severity
- Confidence
- Evidence quality
- Exploitability
- Blast radius
- Affected asset
- Evidence
- Attack path
- Remediation
- Framework mappings
- Policy status
```

## Example Hardening Output

```markdown
## Priority 0 — Emergency

- Disable non-loopback Gateway exposure or require strong auth immediately.
- Set `gateway.bind=127.0.0.1` unless intentionally fronted by trusted proxy or tailnet.
- Disable `config.patch` and elevated runtime tools in untrusted contexts.
- Set `session.dmScope=per-channel-peer` or stricter.
- Quarantine suspicious skills with both credential access and network egress.

## Priority 1 — Production Hardening

- Run OpenClaw as non-root.
- Enforce Docker/Kubernetes sandboxing.
- Add egress allowlist.
- Pin all MCP server versions.
- Move long-lived secrets into external secret manager.
- Enable audit logging and transcript redaction.

## Priority 2 — Assurance

- Generate SBOM.
- Sign approved skill and MCP manifests.
- Require CI SARIF gate on every deployment repo.
- Store audit reports as compliance evidence.
```

## Acceptance Criteria

- Markdown output includes prioritized hardening plan.
- JSON output remains machine-readable.
- SARIF output remains suitable for GitHub code scanning.
- Findings are grouped by attack path and severity.
- Reports distinguish confirmed risks from review items.

---

# Phase 11 — Framework Mapping Enhancements

## Objective

Preserve and improve CSA relevance.

The repo already maps findings to security frameworks. Expand this to support stronger CSA positioning.

## Suggested Mapping Fields

```json
{
  "framework_mappings": {
    "CSA_AICM": ["AICM_ID_HERE"],
    "CSA_MAESTRO": ["MAESTRO_LAYER_OR_CONTROL"],
    "OWASP_Agentic": ["OWASP_ID_HERE"],
    "MITRE_ATLAS": ["ATLAS_ID_HERE"],
    "NIST_AI_RMF": ["MAP_ID_HERE"],
    "NIST_CSF": ["MAP_ID_HERE"],
    "CIS": ["MAP_ID_HERE"]
  }
}
```

## Acceptance Criteria

- Each new check includes mappings where appropriate.
- If mapping is uncertain, leave blank rather than guessing.
- Markdown report includes mapping summary.
- JSON report includes structured mappings.

---

# Phase 12 — Suggested Roadmap / PR Sequence

## PR 1 — Accuracy Fixes

- Remove empty regex patterns.
- Add benign/malicious fixtures.
- Add regression tests for false positives.

## PR 2 — Profiles

- Add `--profile`.
- Define profile applicability.
- Add CI profile behavior and exit codes.

## PR 3 — Finding Metadata

- Add confidence, evidence quality, exploitability, and blast radius.
- Update JSON, Markdown, and SARIF output.

## PR 4 — Capability Model

- Parse skills, MCP, config, and deployment artifacts into normalized capabilities.
- Output capability summaries.

## PR 5 — Correlated Attack Paths

- Add `OC-PATH-*` checks.
- Implement secret-to-egress, prompt-injection-to-tool-use, public-agent-with-private-network-access, open-DM-with-elevated-tools, and untrusted-MCP-server findings.

## PR 6 — Policy-as-Code

- Add `openclaw-audit.policy.yaml`.
- Add policy validation.
- Add policy-aware CI gate.

## PR 7 — Runtime Probes

- Add opt-in `--runtime-probe`.
- Implement safe checks for exposure and auth enforcement.

## PR 8 — Deployment Hardening Modules

- Add deeper Docker, Kubernetes, systemd, reverse proxy, identity, logging, and IR checks.

## PR 9 — Benchmark Corpus

- Add fixtures and expected findings.
- Add accuracy metrics.

## PR 10 — Report Improvements

- Add executive summary.
- Add prioritized hardening plan.
- Group by attack path and remediation priority.

---

# Non-Goals for Now

Do not implement destructive testing.

Do not exploit vulnerabilities.

Do not send real tool commands through OpenClaw.

Do not exfiltrate data.

Do not require cloud-provider API credentials in the first version.

Do not claim runtime safety unless verified.

Do not suppress risky evidence just because compensating controls exist. Instead, lower severity and explain why.

---

# Definition of Done

The auditor should be considered meaningfully improved when it can:

1. Scan an OpenClaw-related source repo and identify insecure code, skill, MCP, Docker, Kubernetes, and documentation patterns.
2. Scan an OpenClaw implementation repo and identify deployment hardening gaps.
3. Correlate at least five major attack paths:
   - open DM with elevated tools
   - prompt injection to tool use
   - secret-to-egress
   - public agent with private-network browser access
   - untrusted MCP server with broad tools
4. Produce findings with confidence, evidence quality, exploitability, and blast radius.
5. Generate a prioritized hardening plan.
6. Support policy-as-code.
7. Run in CI and fail on policy-defined thresholds.
8. Include a benchmark corpus with false-positive and false-negative regression tests.
9. Support opt-in runtime probes for exposure and auth verification.
10. Produce JSON, SARIF, and Markdown output suitable for engineering, security, and governance audiences.
