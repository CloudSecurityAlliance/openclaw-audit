"""Markdown report matching whitepaper structure."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..models import Finding, ScanReport, ScoreResult, Status, compute_score


def render(report: ScanReport, output_path: Path | None = None) -> str:
    """Render report as Markdown."""
    report.compute_summary()
    s = report.summary
    lines: list[str] = []

    _MODE_LABELS = {
        "repo_only": "Source Code Scan",
        "instance_only": "Instance Audit",
        "auto": "Auto-detected",
    }
    mode_label = _MODE_LABELS.get(report.scan_mode, report.scan_mode)

    if report.scan_mode == "repo_only":
        lines.append("# OpenClaw Source Code Audit Report\n")
    elif report.scan_mode == "instance_only":
        lines.append("# OpenClaw Instance Audit Report\n")
    else:
        lines.append("# OpenClaw Security Audit Report\n")
    lines.append(f"**Target:** `{report.target}`  ")
    lines.append(f"**Context:** {report.context_type}  ")
    lines.append(f"**Scan Mode:** {mode_label}  ")
    lines.append(f"**Total Checks:** {s['total_checks']}\n")

    # Executive summary
    fail_n = s["by_status"].get("FAIL", 0)
    warn_n = s["by_status"].get("WARN", 0)
    pass_n = s["by_status"].get("PASS", 0)

    lines.append("## Executive Summary\n")
    if fail_n == 0 and warn_n == 0:
        lines.append("All security checks passed. The deployment meets the "
                      "CSAI hardening baseline.\n")
    else:
        lines.append(f"The audit identified **{fail_n} failure(s)** and "
                      f"**{warn_n} warning(s)** across {s['total_checks']} checks.\n")

    lines.append("| Status | Count |")
    lines.append("|--------|-------|")
    for st in ["FAIL", "WARN", "PASS", "SKIP"]:
        count = s["by_status"].get(st, 0)
        if count:
            lines.append(f"| {st} | {count} |")
    lines.append("")

    # Severity breakdown (only for actionable findings: FAIL + WARN)
    if fail_n or warn_n:
        actionable_sev: dict[str, int] = {}
        for f in report.findings:
            if f.status in (Status.FAIL, Status.WARN):
                actionable_sev[f.severity.value] = actionable_sev.get(f.severity.value, 0) + 1
        lines.append("### Severity Breakdown\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = actionable_sev.get(sev, 0)
            if count:
                lines.append(f"| {sev} | {count} |")
        lines.append("")

    # Security Posture Summary (scoring)
    score = compute_score(report.findings)
    lines.append("## \U0001f9e0 Security Posture Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Exposure Score | {score.exposure_score} |")
    lines.append(f"| Grade | {score.grade_icon} {score.grade} |")
    lines.append(f"| Confidence | {score.confidence_icon} {score.confidence} |")
    lines.append("")
    if score.key_signals:
        lines.append("**Key Signals:**\n")
        for sig in score.key_signals:
            lines.append(f"- {sig}")
        lines.append("")

    # Findings by category
    by_cat: dict[str, list[Finding]] = {}
    for f in report.findings:
        by_cat.setdefault(f.category, []).append(f)

    for cat in sorted(by_cat.keys()):
        findings = by_cat[cat]
        cat_fails = [f for f in findings if f.status == Status.FAIL]
        cat_warns = [f for f in findings if f.status == Status.WARN]

        if not cat_fails and not cat_warns:
            continue

        lines.append(f"## {cat}\n")

        for f in cat_fails + cat_warns:
            icon = "🔴" if f.status == Status.FAIL else "🟡"
            lines.append(f"### {icon} {f.check_id}: {f.title}\n")
            lines.append(f"**Severity:** {f.severity.value}  ")
            lines.append(f"**Status:** {f.status.value}\n")
            lines.append(f"{f.description}\n")

            if f.evidence:
                lines.append(f"**Evidence:** `{f.evidence}`\n")
            if f.file_path:
                lines.append(f"**File:** `{f.file_path}`\n")
            if f.recommendation:
                lines.append(f"**Recommendation:** {f.recommendation}\n")

            if f.frameworks:
                fm = f.frameworks.to_dict()
                if fm:
                    lines.append("**Framework Mappings:**\n")
                    for k, v in fm.items():
                        if isinstance(v, list):
                            lines.append(f"- {k}: {', '.join(v)}")
                        else:
                            lines.append(f"- {k}: {v}")
                    lines.append("")

    # Passing checks — full detail (same format as warnings/failures)
    passed = [f for f in report.findings if f.status == Status.PASS]
    if passed:
        lines.append("## Passing Checks\n")
        for f in passed:
            lines.append(f"### 🟢 {f.check_id}: {f.title}\n")
            lines.append(f"**Severity:** {f.severity.value}  ")
            lines.append(f"**Status:** {f.status.value}\n")
            lines.append(f"{f.description}\n")

            if f.evidence:
                lines.append(f"**Evidence:** `{f.evidence}`\n")
            if f.file_path:
                lines.append(f"**File:** `{f.file_path}`\n")
            if f.recommendation:
                lines.append(f"**Recommendation:** {f.recommendation}\n")

            if f.frameworks:
                fm = f.frameworks.to_dict()
                if fm:
                    lines.append("**Framework Mappings:**\n")
                    for k, v in fm.items():
                        if isinstance(v, list):
                            lines.append(f"- {k}: {', '.join(v)}")
                        else:
                            lines.append(f"- {k}: {v}")
                    lines.append("")

    # OWASP Agentic Top 10 Coverage
    _OWASP_ASI = {
        "ASI01": "Agent Goal Hijack",
        "ASI02": "Tool Misuse and Exploitation",
        "ASI03": "Identity and Privilege Abuse",
        "ASI04": "Agentic Supply Chain Vulnerabilities",
        "ASI05": "Unexpected Code Execution",
        "ASI06": "Memory and Context Poisoning",
        "ASI07": "Insecure Inter-Agent Communication",
        "ASI08": "Cascading Failures",
        "ASI09": "Human-Agent Trust Exploitation",
        "ASI10": "Rogue Agents",
    }
    lines.append("## OWASP Agentic Top 10 Coverage\n")
    lines.append("| Risk ID | Risk | Findings | Status |")
    lines.append("|---------|------|----------|--------|")
    for asi_id, asi_name in _OWASP_ASI.items():
        related = [f for f in report.findings
                   if f.frameworks and asi_id in f.frameworks.owasp_asi]
        active = [f for f in related if f.status != Status.SKIP]
        fails = sum(1 for f in active if f.status == Status.FAIL)
        warns = sum(1 for f in active if f.status == Status.WARN)
        passes = sum(1 for f in active if f.status == Status.PASS)
        all_skipped = related and not active
        if all_skipped:
            status_str = "N/A (skipped)"
        elif fails:
            status_str = f"FAIL ({fails})"
        elif warns:
            status_str = f"WARN ({warns})"
        elif passes:
            status_str = "PASS"
        else:
            status_str = "N/A"
        ids = sorted(set(f.check_id for f in active))
        lines.append(f"| {asi_id} | {asi_name} | {', '.join(ids) if ids else '—'} | {status_str} |")
    lines.append("")

    # MAESTRO Layer Coverage
    _MAESTRO = {
        "L1": "Foundation Models",
        "L2": "Data Operations",
        "L3": "Agent Frameworks",
        "L4": "Deployment and Infrastructure",
        "L5": "Evaluation and Observability",
        "L6": "Security and Compliance",
        "L7": "Agent Ecosystem",
    }
    lines.append("## MAESTRO Layer Coverage\n")
    lines.append("| Layer | Domain | Findings | Status |")
    lines.append("|-------|--------|----------|--------|")
    for layer_id, layer_name in _MAESTRO.items():
        related = [f for f in report.findings
                   if f.frameworks and layer_id in f.frameworks.maestro]
        active = [f for f in related if f.status != Status.SKIP]
        fails = sum(1 for f in active if f.status == Status.FAIL)
        warns = sum(1 for f in active if f.status == Status.WARN)
        passes = sum(1 for f in active if f.status == Status.PASS)
        all_skipped = related and not active
        if all_skipped:
            status_str = "N/A (skipped)"
        elif fails:
            status_str = f"FAIL ({fails})"
        elif warns:
            status_str = f"WARN ({warns})"
        elif passes:
            status_str = "PASS"
        else:
            status_str = "—"
        ids = sorted(set(f.check_id for f in active))
        lines.append(f"| {layer_id} | {layer_name} | {', '.join(ids) if ids else '—'} | {status_str} |")
    lines.append("")

    # Phase 0 Emergency Checklist
    _PHASE0 = [
        ("Endpoint discovery", ["OC-VER-001", "OC-VER-002"]),
        ("Version verification", ["OC-VER-001"]),
        ("Skill audit", ["OC-SKILL-001", "OC-SKILL-002", "OC-SKILL-004", "OC-SKILL-006"]),
        ("Network visibility", ["OC-CFG-002", "OC-CFG-015", "OC-NET-002"]),
        ("Gateway hardening", ["OC-CFG-001", "OC-CFG-016"]),
        ("Config lockdown", ["OC-SOUL-001", "OC-SOUL-007", "OC-CFG-017"]),
    ]
    lines.append("## Phase 0 Emergency Checklist Alignment\n")
    lines.append("| Phase 0 Control | Related Checks | Status |")
    lines.append("|-----------------|----------------|--------|")
    for control_name, check_ids in _PHASE0:
        related = [f for f in report.findings if f.check_id in check_ids]
        fails = sum(1 for f in related if f.status == Status.FAIL)
        warns = sum(1 for f in related if f.status == Status.WARN)
        if fails:
            status_str = f"FAIL ({fails})"
        elif warns:
            status_str = f"WARN ({warns})"
        elif related:
            status_str = "PASS"
        else:
            status_str = "N/A"
        lines.append(f"| {control_name} | {', '.join(check_ids)} | {status_str} |")
    lines.append("")

    # Footer
    lines.append("---\n")
    lines.append("*Generated by openclaw-audit v1.0.0 — "
                 "CSAI OpenClaw Hardening Guide Compliance Scanner*\n")

    text = "\n".join(lines)
    if output_path:
        output_path.write_text(text, encoding="utf-8")
    return text


# ---------------------------------------------------------------------------
# Master Summary for batch / org scans
# ---------------------------------------------------------------------------

def render_master_summary(
    scored_repos: Sequence[tuple[str, ScoreResult]],
    output_path: Path | None = None,
) -> str:
    """Render a master summary table of all scanned repos.

    *scored_repos* is a sequence of ``(repo_name, ScoreResult)`` tuples.
    The output is sorted best-to-worst (lowest score first), then
    alphabetically for ties.
    """
    sorted_repos = sorted(scored_repos, key=lambda r: (r[1].exposure_score, r[0]))

    lines: list[str] = []
    lines.append("# OpenClaw Variant Security Summary\n")
    lines.append(f"**Repos Scanned:** {len(sorted_repos)}\n")

    # Aggregate grade counts
    grade_counts = {"GREEN": 0, "YELLOW": 0, "RED": 0}
    for _, sc in sorted_repos:
        grade_counts[sc.grade] = grade_counts.get(sc.grade, 0) + 1

    lines.append("### Overview\n")
    lines.append("| Grade | Count |")
    lines.append("|-------|-------|")
    lines.append(f"| \U0001f7e9 GREEN | {grade_counts['GREEN']} |")
    lines.append(f"| \U0001f7e8 YELLOW | {grade_counts['YELLOW']} |")
    lines.append(f"| \U0001f7e5 RED | {grade_counts['RED']} |")
    lines.append("")

    lines.append("### Repo Results\n")
    lines.append("| Repo | Grade | Score | Confidence | Key Signals |")
    lines.append("|------|-------|-------|------------|-------------|")
    for repo_name, sc in sorted_repos:
        signals = "; ".join(sc.key_signals) if sc.key_signals else "—"
        lines.append(
            f"| {repo_name} "
            f"| {sc.grade_icon} {sc.grade} "
            f"| {sc.exposure_score} "
            f"| {sc.confidence_icon} {sc.confidence} "
            f"| {signals} |"
        )
    lines.append("")

    lines.append("---\n")
    lines.append("*Generated by openclaw-audit v1.0.0 — "
                 "CSAI OpenClaw Hardening Guide Compliance Scanner*\n")

    text = "\n".join(lines)
    if output_path:
        output_path.write_text(text, encoding="utf-8")
    return text
