#!/usr/bin/env bash
#
# cron_refresh_leaderboard.sh — unattended weekly leaderboard refresh for a
# dedicated server / CI runner.
#
# What it does, in order:
#   1. Syncs the checkout to the latest origin/main (picks up manually-pushed code)
#   2. Ensures a .venv with the package installed
#   3. Runs the full pipeline: discover -> scan -> build -> publish -> push docs
#
# It pushes ONLY leaderboard data (docs/, site-data/, CSVs) to main — never
# code. Code is pushed manually. Concurrent runs are prevented with a lock.
#
# Schedule it from crontab (weekly, Sundays 02:00):
#   0 2 * * 0 /srv/openclaw-audit/scripts/cron_refresh_leaderboard.sh
#
# Optional environment overrides:
#   OPENCLAW_AUDIT_DIR   repo checkout to operate in (default: this script's repo)
#   OPENCLAW_BRANCH      branch to publish to        (default: main)
#   OPENCLAW_LOG_DIR     where logs are written      (default: <repo>/reports/cron)
#   OPENCLAW_WORKERS     parallel scan workers       (default: 8)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${OPENCLAW_AUDIT_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
BRANCH="${OPENCLAW_BRANCH:-main}"
LOG_DIR="${OPENCLAW_LOG_DIR:-$REPO_ROOT/reports/cron}"
WORKERS="${OPENCLAW_WORKERS:-8}"

unset GITHUB_TOKEN || true

mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/refresh_$(date +%Y%m%d_%H%M%S).log"

# Send all output to the log file as well as stdout.
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== cron leaderboard refresh @ $(date) ==="
echo "repo:   $REPO_ROOT"
echo "branch: $BRANCH"
echo "log:    $LOG_FILE"

cd "$REPO_ROOT"

# --- Prevent overlapping runs ---------------------------------------------
# A weekly full scan can run for hours; never let two stack up.
LOCK="$REPO_ROOT/.refresh.lock"
if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK"
    if ! flock -n 9; then
        echo "Another refresh is already running (lock held). Exiting."
        exit 0
    fi
fi

# --- Sync checkout to latest origin/<branch> ------------------------------
# Bail if there are uncommitted changes — on a dedicated automation checkout
# the tree should be clean between runs (each run commits its own outputs).
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "ERROR: working tree has uncommitted tracked changes; refusing to sync." >&2
    git status --short
    exit 1
fi
echo "Syncing to origin/$BRANCH ..."
git fetch --quiet origin
git checkout --quiet "$BRANCH"
git pull --ff-only --quiet origin "$BRANCH"
echo "  now at $(git rev-parse --short HEAD)"

# --- Ensure venv ----------------------------------------------------------
if [[ ! -x "$REPO_ROOT/.venv/bin/python" ]]; then
    echo "Creating virtualenv ..."
    python3 -m venv "$REPO_ROOT/.venv"
fi
"$REPO_ROOT/.venv/bin/python" -m pip install --quiet --upgrade pip
"$REPO_ROOT/.venv/bin/python" -m pip install --quiet -e "$REPO_ROOT"

# --- Run the pipeline -----------------------------------------------------
# Weekly + re-discover + full re-scan, then publish docs/ and push to branch.
"$SCRIPT_DIR/refresh_leaderboard.sh" \
    --discover --force --workers "$WORKERS" \
    --push --branch "$BRANCH"

echo "=== refresh complete @ $(date) ==="
