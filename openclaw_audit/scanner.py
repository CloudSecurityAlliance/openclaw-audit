"""Scanner orchestrator — runs all checks and produces a report."""

from __future__ import annotations

from .checks import agent_safety, config, credentials, docker_audit, mcp, permissions, skills, soul, version
from .context import detect_context
from .mappings import CHECKS
from .models import (
    Applicability, ContextType, Finding, FixLevel, ScanContext, ScanMode,
    ScanReport, Severity, Status, enrich_finding,
)
from .fix.remediate import apply_fixes

from pathlib import Path


ALL_CHECK_MODULES = [
    config,
    soul,
    skills,
    mcp,
    permissions,
    credentials,
    docker_audit,
    version,
    agent_safety,
]


def _effective_applicability(scan_mode: ScanMode, context_type: ContextType) -> Applicability | None:
    """Determine which applicability filter to use.

    Returns the Applicability value to filter on, or None to run all checks.
    """
    if scan_mode == ScanMode.REPO_ONLY:
        return Applicability.REPO_ONLY
    if scan_mode == ScanMode.INSTANCE_ONLY:
        return Applicability.INSTANCE_ONLY
    # AUTO mode: infer from detected context
    if context_type == ContextType.GIT_REPO:
        return Applicability.REPO_ONLY
    if context_type == ContextType.INSTALLED_INSTANCE:
        return Applicability.INSTANCE_ONLY
    # HYBRID or UNKNOWN — run everything
    return None


def _should_skip(check_id: str, app_filter: Applicability | None) -> bool:
    """Return True if this check should be skipped given the applicability filter."""
    if app_filter is None:
        return False
    check = CHECKS.get(check_id)
    if check is None:
        return False
    if check.applicability == Applicability.BOTH:
        return False
    return check.applicability != app_filter


def scan(target: Path, fix: bool = False, fix_level: FixLevel = FixLevel.COMPLETE,
         dry_run: bool = False, scan_mode: ScanMode = ScanMode.AUTO) -> ScanReport:
    """Run all applicable checks against the target."""
    ctx = detect_context(target, scan_mode=scan_mode)
    ctx.scan_mode = scan_mode

    # Build capability profiles up front so correlation checks can use them.
    from .capabilities import build_profiles
    ctx.capability_profiles = build_profiles(ctx)

    # Determine applicability filter
    app_filter = _effective_applicability(scan_mode, ctx.context_type)

    findings: list[Finding] = []
    for module in ALL_CHECK_MODULES:
        try:
            module_findings = module.run(ctx)
            # Filter out checks that don't apply to current scan mode
            for f in module_findings:
                if _should_skip(f.check_id, app_filter):
                    f.status = Status.SKIP
                    f.detail = f"Skipped (not applicable in {scan_mode.value} mode)"
                    f.evidence = ""
                    f.recommendation = ""
                findings.append(f)
        except Exception as e:
            findings.append(Finding(
                check_id=f"ERR-{module.__name__.split('.')[-1].upper()}",
                status=Status.ERROR,
                title=f"Error in {module.__name__}",
                severity=Severity.INFO,
                category="Internal",
                description=str(e),
            ))

    # Deduplicate findings (same check_id + file_path)
    seen = set()
    deduped: list[Finding] = []
    for f in findings:
        key = (f.check_id, f.file_path, f.status.value)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    findings = deduped

    # Correlated attack-path findings (OC-PATH-*) run as a post-pass over the
    # full findings list plus the capability profiles. Respect the same
    # applicability filter as the single-signal checks.
    from .checks import attack_paths
    path_findings = attack_paths.correlate(ctx, findings)
    for f in path_findings:
        if not _should_skip(f.check_id, app_filter):
            findings.append(f)

    # Enrich every finding with triage metadata (confidence, evidence quality,
    # exploitability, blast radius) — derived from the check definition and
    # namespace defaults unless a check set them explicitly.
    for f in findings:
        enrich_finding(f, CHECKS.get(f.check_id))

    # Apply fixes if requested
    fix_actions: list[str] = []
    if fix:
        fix_actions = apply_fixes(ctx, findings, fix_level, dry_run)

    report = ScanReport(
        target=str(target),
        context_type=ctx.context_type.value,
        scan_mode=scan_mode.value,
        findings=findings,
        capability_profiles=[p.to_dict() for p in ctx.capability_profiles],
    )
    report.compute_summary()

    if fix_actions:
        report.summary["fix_actions"] = fix_actions

    return report
