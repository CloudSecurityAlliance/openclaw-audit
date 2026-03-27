"""CLI entry point for the OpenClaw Security Audit Tool."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import FixLevel
from .scanner import scan
from .reports import terminal, json_out, sarif, markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="openclaw-audit",
        description="OpenClaw Security Audit Tool — CSAI Hardening Guide Compliance Scanner",
        epilog="Based on the CSAI 'Hardening OpenClaw' whitepaper. "
               "Maps findings to OWASP ASI, MITRE ATLAS, and CSA AICM.",
    )

    parser.add_argument(
        "target",
        type=Path,
        help="Path to OpenClaw installation (~/.openclaw) or deployment repo",
    )

    parser.add_argument(
        "-f", "--format",
        choices=["terminal", "json", "sarif", "markdown", "all"],
        default="terminal",
        help="Output format (default: terminal)",
    )

    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output file path (for json/sarif/markdown formats)",
    )

    parser.add_argument(
        "--fix",
        action="store_true",
        help="Apply auto-fixes (default: report only)",
    )

    parser.add_argument(
        "--fix-level",
        choices=["basic", "medium", "complete"],
        default="complete",
        help="Fix aggressiveness level (default: complete when --fix is used)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what fixes would be applied without making changes",
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress terminal output (useful with --format json -o file.json)",
    )

    args = parser.parse_args(argv)

    if not args.target.exists():
        print(f"Error: Target path does not exist: {args.target}", file=sys.stderr)
        return 1

    # Run scan
    fix_level = FixLevel(args.fix_level)
    report = scan(
        target=args.target,
        fix=args.fix or args.dry_run,
        fix_level=fix_level,
        dry_run=args.dry_run,
    )

    # Output
    fmt = args.format

    if fmt == "terminal" or fmt == "all":
        if not args.quiet:
            terminal.render(report)

    if fmt == "json" or fmt == "all":
        out_path = args.output
        if fmt == "all" and args.output:
            out_path = args.output.with_suffix(".json")
        text = json_out.render(report, out_path)
        if fmt == "json" and not out_path and not args.quiet:
            print(text)

    if fmt == "sarif" or fmt == "all":
        out_path = args.output
        if fmt == "all" and args.output:
            out_path = args.output.with_suffix(".sarif")
        text = sarif.render(report, out_path)
        if fmt == "sarif" and not out_path and not args.quiet:
            print(text)

    if fmt == "markdown" or fmt == "all":
        out_path = args.output
        if fmt == "all" and args.output:
            out_path = args.output.with_suffix(".md")
        text = markdown.render(report, out_path)
        if fmt == "markdown" and not out_path and not args.quiet:
            print(text)

    # Print fix actions if any
    if (args.fix or args.dry_run) and not args.quiet:
        actions = report.summary.get("fix_actions", [])
        if actions:
            print(f"\n{'[DRY RUN] ' if args.dry_run else ''}Fix actions ({len(actions)}):")
            for a in actions:
                print(f"  • {a}")
            print()

    # Exit code: 1 if any failures, 0 otherwise
    fail_count = report.summary.get("by_status", {}).get("FAIL", 0)
    return 1 if fail_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
