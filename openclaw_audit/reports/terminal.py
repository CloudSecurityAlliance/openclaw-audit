"""Terminal output reporter with colored pass/warn/fail."""

from __future__ import annotations

import sys

from ..models import Finding, ScanReport, Status

# ANSI colors
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_GRAY = "\033[90m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _status_color(s: Status) -> str:
    return {
        Status.FAIL: _RED,
        Status.WARN: _YELLOW,
        Status.PASS: _GREEN,
        Status.SKIP: _GRAY,
        Status.ERROR: _RED,
    }.get(s, _RESET)


def _severity_badge(sev: str) -> str:
    colors = {
        "CRITICAL": _RED + _BOLD,
        "HIGH": _RED,
        "MEDIUM": _YELLOW,
        "LOW": _CYAN,
        "INFO": _GRAY,
    }
    c = colors.get(sev, _RESET)
    return f"{c}{sev}{_RESET}"


def render(report: ScanReport, file=None) -> None:
    """Print the report to terminal."""
    out = file or sys.stdout
    report.compute_summary()
    s = report.summary

    print(f"\n{_BOLD}{'=' * 70}{_RESET}", file=out)
    print(f"{_BOLD}  OpenClaw Security Audit Report{_RESET}", file=out)
    print(f"{_BOLD}{'=' * 70}{_RESET}", file=out)
    print(f"  Target:  {report.target}", file=out)
    print(f"  Context: {report.context_type}", file=out)
    print(f"  Checks:  {s['total_checks']}", file=out)
    print(file=out)

    # Summary bar
    fail_n = s["by_status"].get("FAIL", 0)
    warn_n = s["by_status"].get("WARN", 0)
    pass_n = s["by_status"].get("PASS", 0)
    skip_n = s["by_status"].get("SKIP", 0)

    print(f"  {_RED}{_BOLD}FAIL: {fail_n}{_RESET}  "
          f"{_YELLOW}WARN: {warn_n}{_RESET}  "
          f"{_GREEN}PASS: {pass_n}{_RESET}  "
          f"{_GRAY}SKIP: {skip_n}{_RESET}", file=out)
    print(file=out)

    # Group by category, show failures/warnings first
    by_cat: dict[str, list[Finding]] = {}
    for f in report.findings:
        by_cat.setdefault(f.category, []).append(f)

    for cat, findings in sorted(by_cat.items()):
        cat_fail = sum(1 for f in findings if f.status == Status.FAIL)
        cat_warn = sum(1 for f in findings if f.status == Status.WARN)
        cat_pass = sum(1 for f in findings if f.status == Status.PASS)

        header_color = _RED if cat_fail else (_YELLOW if cat_warn else _GREEN)
        print(f"{_BOLD}  [{cat}]{_RESET} "
              f"{_RED}{cat_fail}F{_RESET} "
              f"{_YELLOW}{cat_warn}W{_RESET} "
              f"{_GREEN}{cat_pass}P{_RESET}", file=out)

        # Show non-passing findings with detail
        for f in findings:
            if f.status in (Status.PASS, Status.SKIP):
                continue
            sc = _status_color(f.status)
            print(f"    {sc}{f.status.value:5}{_RESET} "
                  f"{_severity_badge(f.severity.value):>20} "
                  f"{f.check_id} {f.title}", file=out)
            if f.evidence:
                print(f"           {_GRAY}Evidence: {f.evidence}{_RESET}", file=out)
            if f.recommendation:
                print(f"           {_CYAN}Fix: {f.recommendation}{_RESET}", file=out)

        # Compact pass/skip summary
        passed = [f for f in findings if f.status == Status.PASS]
        if passed:
            ids = ", ".join(f.check_id for f in passed)
            print(f"    {_GREEN} PASS{_RESET}  {_GRAY}{ids}{_RESET}", file=out)

        print(file=out)

    # Overall verdict
    print(f"{_BOLD}{'─' * 70}{_RESET}", file=out)
    if fail_n == 0 and warn_n == 0:
        print(f"  {_GREEN}{_BOLD}✓ All checks passed{_RESET}", file=out)
    elif fail_n == 0:
        print(f"  {_YELLOW}{_BOLD}⚠ {warn_n} warning(s), no failures{_RESET}", file=out)
    else:
        print(f"  {_RED}{_BOLD}✗ {fail_n} failure(s), {warn_n} warning(s){_RESET}", file=out)
    print(f"{_BOLD}{'─' * 70}{_RESET}\n", file=out)
