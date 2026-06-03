#!/usr/bin/env bash
#
# refresh_leaderboard.sh — end-to-end RiskRubric leaderboard pipeline.
#
# Stages (each can be skipped via flags):
#   1. discover  — find OpenClaw variants on GitHub  -> reports/openclaw_variants_latest.csv
#   2. scan      — clone + audit every repo (v3)      -> reports/batch_scans/<slug>/
#   3. summary   — aggregate per-repo JSON            -> site-data/leaderboard-summary.json
#   4. site      — render the static site             -> output/riskrubric-site/
#   5. publish   — sync the rendered site into        -> docs/  (GitHub Pages source)
#   6. git       — commit (and optionally push) docs/ + site-data + CSV
#
# Examples:
#   scripts/refresh_leaderboard.sh                       # scan new repos, build, publish to docs/, commit
#   scripts/refresh_leaderboard.sh --discover --force    # full refresh: re-discover + re-scan everything
#   scripts/refresh_leaderboard.sh --skip-scan           # just rebuild + publish from existing reports
#   scripts/refresh_leaderboard.sh --push --branch main  # commit AND push to main (goes live on Pages)
#   scripts/refresh_leaderboard.sh --no-commit           # build + publish to docs/ but touch no git state

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# An invalid GITHUB_TOKEN in the environment shadows the gh keyring login and
# can interfere with git over HTTPS; clear it so keyring/credential-helper auth
# is used. Public clones need no auth at all.
unset GITHUB_TOKEN || true

# Prefer the project venv if present.
if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    PY="$REPO_ROOT/.venv/bin/python"
else
    PY="python3"
fi

# --- defaults ---
DO_DISCOVER=false
DO_SCAN=true
FORCE=false
WORKERS=8
DO_COMMIT=true
DO_PUSH=false
BRANCH=""
MESSAGE=""

usage() {
    # Print the leading comment block (after the shebang) up to the first
    # non-comment line.
    awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}"
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --discover)   DO_DISCOVER=true; shift ;;
        --skip-scan)  DO_SCAN=false; shift ;;
        --force)      FORCE=true; shift ;;
        --workers)    WORKERS="$2"; shift 2 ;;
        --no-commit)  DO_COMMIT=false; shift ;;
        --push)       DO_PUSH=true; shift ;;
        --branch)     BRANCH="$2"; shift 2 ;;
        --message|-m) MESSAGE="$2"; shift 2 ;;
        -h|--help)    usage 0 ;;
        *) echo "Unknown option: $1" >&2; usage 1 ;;
    esac
done

log() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

CSV="$REPO_ROOT/reports/openclaw_variants_latest.csv"
SUMMARY="$REPO_ROOT/site-data/leaderboard-summary.json"
SITE_DIR="$REPO_ROOT/output/riskrubric-site"
DOCS="$REPO_ROOT/docs"

# --- Stage 1: discover -----------------------------------------------------
if $DO_DISCOVER; then
    log "Stage 1/6: discover OpenClaw variants"
    # Archive the current list (dated) before discovery overwrites it.
    if [[ -f "$CSV" ]]; then
        STAMP="$(date +%Y%m%d_%H%M%S)"
        cp -L "$CSV" "$REPO_ROOT/reports/openclaw_variants_${STAMP}.csv"
        echo "  archived previous list -> reports/openclaw_variants_${STAMP}.csv"
    fi
    "$PY" "$SCRIPT_DIR/discover_openclaw_repos.py"
else
    log "Stage 1/6: discover — skipped (using existing $CSV)"
fi

if [[ ! -f "$CSV" ]]; then
    echo "ERROR: repo list not found: $CSV (run with --discover first)" >&2
    exit 1
fi
REPO_COUNT="$(tail -n +2 "$CSV" | grep -c . || true)"
echo "  repo list: $REPO_COUNT repos"

# --- Stage 2: scan ---------------------------------------------------------
if $DO_SCAN; then
    log "Stage 2/6: scan ($WORKERS workers, force=$FORCE)"
    SCAN_ARGS=(--workers "$WORKERS" --no-build --csv "$CSV")
    $FORCE && SCAN_ARGS+=(--force)
    "$PY" "$SCRIPT_DIR/run_parallel_batch_scan.py" "${SCAN_ARGS[@]}"
else
    log "Stage 2/6: scan — skipped"
fi

# --- Stage 3: summary ------------------------------------------------------
log "Stage 3/6: build leaderboard summary"
"$PY" "$SCRIPT_DIR/build_leaderboard_summary.py"

# --- Stage 4: site ---------------------------------------------------------
log "Stage 4/6: build site"
"$PY" "$SCRIPT_DIR/build_riskrubric_site.py"

# --- Stage 5: publish to docs/ --------------------------------------------
log "Stage 5/6: publish rendered site into docs/"
if [[ ! -d "$SITE_DIR" ]]; then
    echo "ERROR: rendered site not found: $SITE_DIR" >&2
    exit 1
fi
# Sync per-repo pages, pruning stale ones, while leaving docs/ logos & infra
# files (CNAME, svgs, source PNGs) untouched.
rsync -a --delete --include='rr-repo-*.html' --exclude='*' "$SITE_DIR/" "$DOCS/"
# Copy the homepage, summary JSON, and the two generated logo PNGs.
cp -p "$SITE_DIR/index.html" "$DOCS/index.html"
cp -p "$SITE_DIR/leaderboard-summary.json" "$DOCS/leaderboard-summary.json"
for png in "$SITE_DIR"/*.png; do
    [[ -e "$png" ]] && cp -p "$png" "$DOCS/"
done
echo "  docs/ updated ($(ls "$DOCS"/rr-repo-*.html 2>/dev/null | wc -l | tr -d ' ') report pages)"

# --- Stage 6: git ----------------------------------------------------------
if ! $DO_COMMIT; then
    log "Stage 6/6: git — skipped (--no-commit)"
    echo "Done. Review docs/ and commit when ready."
    exit 0
fi

log "Stage 6/6: commit$($DO_PUSH && echo ' + push')"
[[ -n "$BRANCH" ]] && git checkout "$BRANCH"

git add docs site-data/leaderboard-summary.json \
    reports/openclaw_variants_latest.csv reports/openclaw_variants_*.csv 2>/dev/null || true

if git diff --cached --quiet; then
    echo "  no changes to commit"
else
    : "${MESSAGE:=Regenerate RiskRubric leaderboard: ${REPO_COUNT} repos ($(date +%F))}"
    git commit -m "$MESSAGE" -m "Generated by scripts/refresh_leaderboard.sh"
    echo "  committed: $MESSAGE"
    if $DO_PUSH; then
        TARGET="${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
        git push origin "$TARGET"
        echo "  pushed to origin/$TARGET"
    else
        echo "  (not pushed — re-run with --push, or 'git push' manually)"
    fi
fi
