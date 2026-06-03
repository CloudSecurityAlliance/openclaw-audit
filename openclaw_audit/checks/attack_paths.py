"""Correlated attack-path checks (OC-PATH-001 .. OC-PATH-007).

Unlike the single-signal checks, these run as a post-pass over the full
findings list and the capability profiles, so they can reason about
*combinations* of exposure, capability, and supply-chain posture.
"""

from __future__ import annotations

from pathlib import Path

from .. import capabilities as cap
from ..mappings import CHECKS
from ..models import Finding, ScanContext, Severity, Status


def _make(check_id: str, detail: str = "", evidence: str = "",
          file_path: str = "", attack_path: str = "") -> Finding:
    c = CHECKS[check_id]
    return Finding(
        check_id=check_id, status=Status.FAIL, title=c.title,
        severity=c.severity, category=c.category, description=c.description,
        detail=detail, evidence=evidence, file_path=file_path,
        recommendation=c.recommendation, frameworks=c.frameworks,
        attack_path=attack_path,
    )


def _fails_by_file(findings: list[Finding]) -> dict[str, set[str]]:
    """Map file_path -> set of FAILed check ids touching that file."""
    out: dict[str, set[str]] = {}
    for f in findings:
        if f.status == Status.FAIL and f.file_path:
            out.setdefault(f.file_path, set()).add(f.check_id)
    return out


def _failed_ids(findings: list[Finding]) -> set[str]:
    return {f.check_id for f in findings if f.status == Status.FAIL}


# Capabilities that make injected instructions dangerous.
_PRIVILEGED_CAPS = frozenset({
    cap.SHELL_EXEC, cap.NETWORK_POST, cap.NETWORK_GET, cap.WRITE_FILE,
    cap.CREDENTIAL_READ, cap.SSH_KEY_READ, cap.CLOUD_TOKEN_READ,
    cap.ENV_READ, cap.MCP_TOOL_CALL,
})


def _same_asset_fails(profile, fails_by_file: dict[str, set[str]]) -> set[str]:
    """FAILed check ids attributable to the same asset as *profile*.

    Matches on the exact file and on the asset's containing directory, so a
    skill whose findings point at SKILL.md still correlates with its profile.
    """
    ids: set[str] = set()
    pf = profile.file_path
    if not pf:
        return ids
    pdir = str(Path(pf).parent)
    for fp, cids in fails_by_file.items():
        if fp == pf or str(Path(fp).parent) == pdir or fp.startswith(pdir):
            ids |= cids
    return ids


def correlate(ctx: ScanContext, findings: list[Finding]) -> list[Finding]:
    profiles = ctx.capability_profiles or []
    failed = _failed_ids(findings)
    fails_by_file = _fails_by_file(findings)
    results: list[Finding] = []

    # Config file path for config-derived paths (001, 004).
    cfg_fp = str(ctx.config_files[0]) if ctx.config_files else ""

    # --- OC-PATH-001: open DM + elevated tools + non-isolated sessions ---
    open_dm = "OC-CFG-009" in failed
    elevated = "OC-CFG-008" in failed or "OC-CFG-004" in failed
    not_isolated = "OC-CFG-010" in failed
    if open_dm and elevated and not_isolated:
        contributors = sorted(
            {"OC-CFG-009", "OC-CFG-010"}
            | ({"OC-CFG-008"} & failed) | ({"OC-CFG-004"} & failed)
        )
        results.append(_make(
            "OC-PATH-001",
            evidence="Open dmPolicy + elevated/shell tools + non-isolated DM "
                     f"sessions ({', '.join(contributors)})",
            file_path=cfg_fp,
            attack_path="open_dm -> elevated_tool_use",
        ))

    # --- OC-PATH-004: public agent + private-network browser + weak auth ---
    exposed = "OC-CFG-002" in failed
    private_browser = "OC-CFG-011" in failed
    weak_auth = "OC-CFG-001" in failed
    if exposed and private_browser and weak_auth:
        results.append(_make(
            "OC-PATH-004",
            evidence="Non-loopback gateway bind (OC-CFG-002) + browser private "
                     "network access (OC-CFG-011) + no/weak gateway auth "
                     "(OC-CFG-001)",
            file_path=cfg_fp,
            attack_path="public_gateway -> ssrf_internal_network",
        ))

    # --- Per-asset correlations over capability profiles ---
    for p in profiles:
        same = _same_asset_fails(p, fails_by_file)
        privileged_caps = sorted(p.capabilities & _PRIVILEGED_CAPS)

        # OC-PATH-002: injection in this asset + privileged capability.
        inj = same & {"OC-SKILL-001", "OC-MCP-004"}
        if inj and privileged_caps:
            results.append(_make(
                "OC-PATH-002",
                evidence=f"{p.asset}: injection ({', '.join(sorted(inj))}) with "
                         f"capabilities {privileged_caps}",
                file_path=p.file_path,
                attack_path="prompt_injection -> tool_use",
            ))

        # OC-PATH-003: secret read + egress in the same asset.
        if p.reads_secrets() and p.has_egress():
            srcs = ", ".join(p.sensitive_sources[:5]) or "credential capability"
            results.append(_make(
                "OC-PATH-003",
                evidence=f"{p.asset}: reads sensitive sources ({srcs}) and can "
                         f"egress (caps: {sorted(p.capabilities & cap.EGRESS_CAPS)})",
                file_path=p.file_path,
                attack_path="secret_read -> network_egress",
            ))

        # OC-PATH-005: untrusted MCP (public + unpinned) with broad tools.
        if p.asset_type == "mcp_server" and p.trust_boundary == "public_mcp":
            mcp_supply_fail = same & {"OC-MCP-002", "OC-MCP-005"}
            broad = len(p.capabilities) >= 2  # mcp_tool_call + at least one more
            if "OC-MCP-002" in same and ("OC-MCP-005" in failed or mcp_supply_fail):
                results.append(_make(
                    "OC-PATH-005",
                    detail="broad tool capabilities" if broad else "",
                    evidence=f"{p.asset}: public registry + unpinned version "
                             f"({', '.join(sorted(mcp_supply_fail))}); "
                             f"capabilities {sorted(p.capabilities)}",
                    file_path=p.file_path,
                    attack_path="untrusted_mcp -> broad_tool_access",
                ))

        # OC-PATH-006: remote code download to execution.
        if cap.REMOTE_CODE_DOWNLOAD in p.capabilities:
            results.append(_make(
                "OC-PATH-006",
                evidence=f"{p.asset}: downloads and executes remote content "
                         "(pipe-to-shell or defanged URL)",
                file_path=p.file_path,
                attack_path="remote_download -> execution",
            ))

        # OC-PATH-007: session transcript leakage.
        transcript_read = cap.SESSION_TRANSCRIPT_READ in p.capabilities
        transcript_write = cap.SESSION_TRANSCRIPT_WRITE in p.capabilities
        if (transcript_read and p.has_egress()) or (
            transcript_write and (p.has_egress() or cap.has_paste_sink(p))
        ):
            results.append(_make(
                "OC-PATH-007",
                evidence=f"{p.asset}: session transcript access combined with "
                         "an external sink",
                file_path=p.file_path,
                attack_path="session_transcript -> external_sink",
            ))

    return results
