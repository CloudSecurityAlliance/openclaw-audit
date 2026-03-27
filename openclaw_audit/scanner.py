"""Scanner orchestrator — runs all checks and produces a report."""

from __future__ import annotations

from .checks import config, credentials, docker_audit, mcp, permissions, skills, soul, version
from .context import detect_context
from .models import ContextType, Finding, FixLevel, ScanContext, ScanReport, Status
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
]


def scan(target: Path, fix: bool = False, fix_level: FixLevel = FixLevel.COMPLETE,
         dry_run: bool = False) -> ScanReport:
    """Run all applicable checks against the target."""
    ctx = detect_context(target)

    findings: list[Finding] = []
    for module in ALL_CHECK_MODULES:
        try:
            module_findings = module.run(ctx)
            findings.extend(module_findings)
        except Exception as e:
            from .models import Severity
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

    # Apply fixes if requested
    fix_actions: list[str] = []
    if fix:
        fix_actions = apply_fixes(ctx, findings, fix_level, dry_run)

    report = ScanReport(
        target=str(target),
        context_type=ctx.context_type.value,
        findings=findings,
    )
    report.compute_summary()

    if fix_actions:
        report.summary["fix_actions"] = fix_actions

    return report
