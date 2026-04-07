#!/usr/bin/env bash
# Batch scan ALL repos from openclaw_variants_latest.csv using --repo-only mode.
# Each repo gets its own report directory in reports/batch_scans/.
# Skips repos that already have a .json report (use --force to rescan all).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CSV_FILE="$SCRIPT_DIR/reports/openclaw_variants_latest.csv"
OUTPUT_DIR="$SCRIPT_DIR/reports/batch_scans"
LOG_FILE="$OUTPUT_DIR/batch_scan_full.log"
FORCE=false
PARALLEL=4

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force) FORCE=true; shift ;;
        --parallel) PARALLEL="$2"; shift 2 ;;
        *) echo "Usage: $0 [--force] [--parallel N]"; exit 1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"

if [[ ! -f "$CSV_FILE" ]]; then
    echo "ERROR: CSV file not found: $CSV_FILE" >&2
    exit 1
fi

# Extract repo names from CSV (skip header, first column is full_name)
REPOS=()
while IFS=, read -r full_name rest; do
    # Skip header
    [[ "$full_name" == "full_name" ]] && continue
    # Trim quotes and whitespace
    full_name="${full_name//\"/}"
    full_name="$(echo "$full_name" | xargs)"
    [[ -z "$full_name" ]] && continue
    REPOS+=("$full_name")
done < "$CSV_FILE"

TOTAL=${#REPOS[@]}

echo "=========================================="
echo "  OpenClaw Full Batch Repo Scanner"
echo "=========================================="
echo "  CSV:      $CSV_FILE"
echo "  Repos:    $TOTAL"
echo "  Output:   $OUTPUT_DIR"
echo "  Parallel: $PARALLEL"
echo "  Force:    $FORCE"
echo "=========================================="
echo ""

PASS_COUNT=0
FAIL_COUNT=0
ERROR_COUNT=0
SKIP_COUNT=0

# Truncate log
: > "$LOG_FILE"

scan_repo() {
    local i="$1"
    local repo="$2"
    local SLUG="${repo//\//-}"
    local REPORT_DIR="$OUTPUT_DIR/$SLUG"

    # Skip if already scanned (unless --force)
    if [[ "$FORCE" != "true" && -f "$REPORT_DIR/$SLUG.json" ]]; then
        echo "[$i/$TOTAL] $repo — SKIP (already scanned)"
        echo "SKIP $repo" >> "$LOG_FILE"
        return 2
    fi

    mkdir -p "$REPORT_DIR"

    echo "[$i/$TOTAL] $repo"

    python3 -m openclaw_audit \
        --clone "$repo" \
        --repo-only \
        --format all \
        --output "$REPORT_DIR/$SLUG" \
        --quiet \
        2>&1 | tee -a "$LOG_FILE"
    local EXIT_CODE=${PIPESTATUS[0]}

    if [[ $EXIT_CODE -eq 0 ]]; then
        echo "  ✓ PASS — $repo"
        return 0
    elif [[ $EXIT_CODE -eq 1 && -f "$REPORT_DIR/$SLUG.json" ]]; then
        echo "  ✗ FINDINGS — $repo"
        return 1
    else
        echo "  ⚠ ERROR — $repo (exit $EXIT_CODE)"
        return 3
    fi
}

for i in "${!REPOS[@]}"; do
    idx=$((i + 1))
    repo="${REPOS[$i]}"

    scan_repo "$idx" "$repo"
    rc=$?

    case $rc in
        0) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        1) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        2) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
        *) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
    esac
done

echo ""
echo "=========================================="
echo "  Full Batch Scan Complete"
echo "=========================================="
echo "  Total:    $TOTAL"
echo "  Clean:    $PASS_COUNT"
echo "  Findings: $FAIL_COUNT"
echo "  Skipped:  $SKIP_COUNT"
echo "  Errors:   $ERROR_COUNT"
echo ""
echo "  Reports:  $OUTPUT_DIR"
echo "  Log:      $LOG_FILE"
echo "=========================================="

# Rebuild summary and site
echo ""
echo "Rebuilding leaderboard summary..."
python3 "$SCRIPT_DIR/scripts/build_leaderboard_summary.py"

echo ""
echo "Rebuilding site..."
python3 "$SCRIPT_DIR/scripts/build_riskrubric_site.py"

echo ""
echo "Done. Run 'open output/riskrubric-site/index.html' to preview."
