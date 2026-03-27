"""CLI entry point for the OpenClaw Security Audit Tool."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from .models import FixLevel
from .remote import (
    parse_remote_target, prompt_password, push_fixes, scan_hosts_file,
    scan_remote,
)
from .scanner import scan
from .reports import terminal, json_out, sarif, markdown


def _consolidate_findings(findings: list) -> list:
    """Consolidate duplicate findings by check_id + status into single entries with counts."""
    from collections import OrderedDict
    consolidated: OrderedDict = OrderedDict()

    for f in findings:
        key = (f.check_id, f.status.value)
        if key in consolidated:
            existing = consolidated[key]
            existing["count"] += 1
            # Collect unique file paths
            if f.file_path and f.file_path not in existing["paths"]:
                existing["paths"].append(f.file_path)
        else:
            consolidated[key] = {
                "finding": f,
                "count": 1,
                "paths": [f.file_path] if f.file_path else [],
            }

    result = []
    for entry in consolidated.values():
        f = entry["finding"]
        count = entry["count"]
        paths = entry["paths"]
        if count > 1:
            f.detail = f"Affects {count} files"
            if paths:
                # Show first few paths in evidence
                path_list = ", ".join(paths[:3])
                if len(paths) > 3:
                    path_list += f", ...and {len(paths) - 3} more"
                if f.evidence:
                    f.evidence += f" [{path_list}]"
                else:
                    f.evidence = path_list
                f.file_path = paths[0]
        result.append(f)

    return result


def _render_report(report, fmt: str, output: Path | None, quiet: bool) -> None:
    """Render a report in the requested format(s)."""
    if fmt == "terminal" or fmt == "all":
        if not quiet:
            terminal.render(report)

    if fmt == "json" or fmt == "all":
        out_path = output
        if fmt == "all" and output:
            out_path = output.with_suffix(".json")
        text = json_out.render(report, out_path)
        if fmt == "json" and not out_path and not quiet:
            print(text)

    if fmt == "sarif" or fmt == "all":
        out_path = output
        if fmt == "all" and output:
            out_path = output.with_suffix(".sarif")
        text = sarif.render(report, out_path)
        if fmt == "sarif" and not out_path and not quiet:
            print(text)

    if fmt == "markdown" or fmt == "all":
        out_path = output
        if fmt == "all" and output:
            out_path = output.with_suffix(".md")
        text = markdown.render(report, out_path)
        if fmt == "markdown" and not out_path and not quiet:
            print(text)


def _print_fix_actions(report, dry_run: bool, quiet: bool) -> None:
    if quiet:
        return
    actions = report.summary.get("fix_actions", [])
    if actions:
        print(f"\n{'[DRY RUN] ' if dry_run else ''}Fix actions ({len(actions)}):")
        for a in actions:
            print(f"  • {a}")
        print()


def _scan_single(target_str: str, args, password: str | None = None) -> int:
    """Scan a single target (local or remote). Returns exit code."""
    remote = parse_remote_target(target_str)

    if remote:
        # Remote target — fetch via SSH, scan locally, optionally push fixes
        local_dir = None
        try:
            if not args.quiet:
                print(f"\n{'─' * 60}")
                print(f"  Remote scan: {remote.display}")
                print(f"{'─' * 60}")

            # Prompt for password if --password flag was used and no password yet
            pw = password
            if args.password and not pw:
                pw = prompt_password(remote)

            local_dir = scan_remote(
                remote, ssh_key=args.ssh_key, password=pw,
                quiet=args.quiet,
            )

            fix_level = FixLevel(args.fix_level)
            report = scan(
                target=local_dir,
                fix=args.fix or args.dry_run,
                fix_level=fix_level,
                dry_run=args.dry_run,
            )
            # Override target name in report to show remote path
            report.target = remote.display

            # Remap temp paths to remote paths in findings and fix actions
            local_prefix = str(local_dir)
            # Also handle /private prefix macOS adds to temp dirs
            private_prefix = "/private" + local_prefix
            for f in report.findings:
                if f.file_path:
                    f.file_path = f.file_path.replace(private_prefix, remote.path)
                    f.file_path = f.file_path.replace(local_prefix, remote.path)
                if f.evidence:
                    f.evidence = f.evidence.replace(private_prefix, remote.path)
                    f.evidence = f.evidence.replace(local_prefix, remote.path)
                if f.fix_description:
                    f.fix_description = f.fix_description.replace(private_prefix, remote.path)
                    f.fix_description = f.fix_description.replace(local_prefix, remote.path)

            # Remap fix action strings too
            fix_actions = report.summary.get("fix_actions", [])
            if fix_actions:
                report.summary["fix_actions"] = [
                    a.replace(private_prefix, remote.path).replace(local_prefix, remote.path)
                    for a in fix_actions
                ]

            # Consolidate duplicate findings (same check_id + status)
            report.findings = _consolidate_findings(report.findings)

            # Determine output path for multi-host mode
            output = args.output
            if args.hosts and output:
                host_slug = remote.host.replace(".", "-")
                output = output / host_slug

            _render_report(report, args.format, output, args.quiet)
            _print_fix_actions(report, args.dry_run, args.quiet)

            # Push fixes back to remote if applied (not dry-run)
            if args.fix and not args.dry_run:
                fix_actions = report.summary.get("fix_actions", [])
                if fix_actions:
                    push_fixes(remote, local_dir,
                               ssh_key=args.ssh_key, password=pw,
                               quiet=args.quiet)
                    if not args.quiet:
                        print(f"  Fixes pushed to {remote.display}")

            fail_count = report.summary.get("by_status", {}).get("FAIL", 0)
            return 1 if fail_count > 0 else 0

        except Exception as e:
            print(f"Error scanning {remote.display}: {e}", file=sys.stderr)
            return 1
        finally:
            if local_dir and local_dir.exists():
                shutil.rmtree(local_dir, ignore_errors=True)

    else:
        # Local target
        target = Path(target_str)
        if not target.exists():
            print(f"Error: Target path does not exist: {target}", file=sys.stderr)
            return 1

        fix_level = FixLevel(args.fix_level)
        report = scan(
            target=target,
            fix=args.fix or args.dry_run,
            fix_level=fix_level,
            dry_run=args.dry_run,
        )

        _render_report(report, args.format, args.output, args.quiet)
        _print_fix_actions(report, args.dry_run, args.quiet)

        fail_count = report.summary.get("by_status", {}).get("FAIL", 0)
        return 1 if fail_count > 0 else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="openclaw-audit",
        description="OpenClaw Security Audit Tool — CSAI Hardening Guide Compliance Scanner",
        epilog="Supports local paths, remote SSH targets (user@host:/path), "
               "and fleet scanning (--hosts file). "
               "Based on the CSAI 'Hardening OpenClaw' whitepaper.",
    )

    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Local path or remote target (user@host:/path). "
             "Omit if using --hosts.",
    )

    parser.add_argument(
        "--hosts",
        type=Path,
        default=None,
        help="File with one target per line for fleet scanning. "
             "Format: user@host:/path or just hostname (defaults to "
             "root@host:/home/openclaw).",
    )

    parser.add_argument(
        "--ssh-key",
        default=None,
        help="Path to SSH private key for remote connections.",
    )

    parser.add_argument(
        "--password", "-p",
        action="store_true",
        help="Prompt for SSH password (for hosts using password auth). "
             "With --hosts, prompts once and reuses for all hosts.",
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
        help="Output file path (for json/sarif/markdown). "
             "With --hosts, this is a directory for per-host reports.",
    )

    parser.add_argument(
        "--fix",
        action="store_true",
        help="Apply auto-fixes (pushed back to remote hosts via SSH).",
    )

    parser.add_argument(
        "--fix-level",
        choices=["basic", "medium", "complete"],
        default="complete",
        help="Fix aggressiveness (default: complete when --fix is used).",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what fixes would be applied without making changes.",
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress terminal output.",
    )

    args = parser.parse_args(argv)

    if not args.target and not args.hosts:
        parser.error("Provide a target path/host or --hosts file.")

    # For password auth, prompt once upfront
    password = None
    if args.password:
        from .remote import RemoteTarget
        if args.target:
            remote = parse_remote_target(args.target)
            if remote:
                password = prompt_password(remote)
        elif args.hosts:
            import getpass
            password = getpass.getpass("  SSH password (used for all hosts): ")

    # Fleet mode: scan multiple hosts
    if args.hosts:
        if not args.hosts.exists():
            print(f"Error: Hosts file not found: {args.hosts}", file=sys.stderr)
            return 1

        targets = scan_hosts_file(args.hosts)
        if not targets:
            print(f"Error: No valid targets in {args.hosts}", file=sys.stderr)
            return 1

        if args.output:
            args.output.mkdir(parents=True, exist_ok=True)

        if not args.quiet:
            print(f"\nFleet scan: {len(targets)} host(s)")

        any_failed = False
        for i, remote in enumerate(targets, 1):
            if not args.quiet:
                print(f"\n[{i}/{len(targets)}] {remote.display}")
            target_str = f"{remote.user}@{remote.host}"
            if remote.port != 22:
                target_str += f":{remote.port}"
            target_str += f":{remote.path}"
            code = _scan_single(target_str, args, password=password)
            if code != 0:
                any_failed = True

        if not args.quiet:
            print(f"\nFleet scan complete: {len(targets)} host(s)")

        return 1 if any_failed else 0

    # Single target mode
    return _scan_single(args.target, args, password=password)


if __name__ == "__main__":
    sys.exit(main())
