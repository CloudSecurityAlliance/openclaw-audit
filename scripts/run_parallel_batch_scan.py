#!/usr/bin/env python3
"""Parallel batch scanner: reads CSV, scans all repos with N workers.

Usage:
    python3 scripts/run_parallel_batch_scan.py [--workers N] [--force] [--csv PATH]

Defaults: 8 workers, skip already-scanned repos.
"""

import argparse
import csv
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = REPO_ROOT / "reports" / "openclaw_variants_latest.csv"
BATCH_DIR = REPO_ROOT / "reports" / "batch_scans"
LOG_FILE = BATCH_DIR / "batch_scan_parallel.log"

lock = threading.Lock()
counts = {"pass": 0, "fail": 0, "skip": 0, "error": 0}


def log(msg: str):
    with lock:
        print(msg, flush=True)
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")


def scan_repo(idx: int, total: int, repo: str, force: bool) -> str:
    slug = repo.replace("/", "-")
    report_dir = BATCH_DIR / slug
    json_path = report_dir / f"{slug}.json"

    if not force and json_path.exists():
        log(f"[{idx}/{total}] SKIP {repo}")
        with lock:
            counts["skip"] += 1
        return "skip"

    report_dir.mkdir(parents=True, exist_ok=True)
    output_prefix = str(report_dir / slug)

    cmd = [
        sys.executable, "-m", "openclaw_audit",
        "--clone", repo,
        "--repo-only",
        "--format", "all",
        "--output", output_prefix,
        "--quiet",
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )

    if result.returncode == 0:
        log(f"[{idx}/{total}] PASS {repo}")
        with lock:
            counts["pass"] += 1
        return "pass"
    elif result.returncode == 1 and json_path.exists():
        log(f"[{idx}/{total}] FINDINGS {repo}")
        with lock:
            counts["fail"] += 1
        return "fail"
    else:
        stderr = (result.stderr or "").strip()[:120]
        log(f"[{idx}/{total}] ERROR {repo} (exit {result.returncode}) — {stderr}")
        with lock:
            counts["error"] += 1
        return "error"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--csv", default=str(CSV_PATH))
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"ERROR: CSV not found: {csv_path}")
        sys.exit(1)

    with open(csv_path, newline="", encoding="utf-8") as f:
        repos = [row["full_name"] for row in csv.DictReader(f) if row.get("full_name")]

    BATCH_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text("")  # Truncate log

    total = len(repos)
    print(f"{'='*50}")
    print(f"  Parallel Batch Scan")
    print(f"  Repos:   {total}")
    print(f"  Workers: {args.workers}")
    print(f"  Force:   {args.force}")
    print(f"  Output:  {BATCH_DIR}")
    print(f"{'='*50}\n")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(scan_repo, i + 1, total, repo, args.force): repo
            for i, repo in enumerate(repos)
        }
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                repo = futures[future]
                log(f"EXCEPTION {repo}: {e}")
                with lock:
                    counts["error"] += 1

    print(f"\n{'='*50}")
    print(f"  Scan Complete")
    print(f"  Total:    {total}")
    print(f"  Pass:     {counts['pass']}")
    print(f"  Findings: {counts['fail']}")
    print(f"  Skipped:  {counts['skip']}")
    print(f"  Errors:   {counts['error']}")
    print(f"{'='*50}\n")

    print("Rebuilding leaderboard summary...")
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "build_leaderboard_summary.py")],
                   check=True, cwd=str(REPO_ROOT))

    print("\nRebuilding site...")
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "build_riskrubric_site.py")],
                   check=True, cwd=str(REPO_ROOT))

    print("\nDone.")


if __name__ == "__main__":
    main()
