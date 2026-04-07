#!/usr/bin/env python3
"""Build leaderboard-summary.json from variant CSV + per-repo JSON audit reports.

Reads:
  - reports/openclaw_variants_latest.csv   (variant discovery data)
  - reports/batch_scans/<folder>/<folder>.json  (per-repo audit JSON)

Writes:
  - site-data/leaderboard-summary.json

Implements all computed fields from openclaw_homepage_views_spec.md v1.
"""

import csv
import json
import math
import os
import re
import sys
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(REPO_ROOT, "reports", "openclaw_variants_latest.csv")
BATCH_DIR = os.path.join(REPO_ROOT, "reports", "batch_scans")
OUTPUT_PATH = os.path.join(REPO_ROOT, "site-data", "leaderboard-summary.json")

# ---------------------------------------------------------------------------
# Check-ID sets for risk flags
# ---------------------------------------------------------------------------

SKILL_CHECK_IDS = {
    "OC-SKILL-001", "OC-SKILL-002", "OC-SKILL-003",
    "OC-SKILL-004", "OC-SKILL-005", "OC-SKILL-006",
}

DOCKER_CHECK_IDS = {
    "OC-DOCK-001", "OC-DOCK-002", "OC-DOCK-003", "OC-DOCK-004",
    "OC-DOCK-005", "OC-DOCK-006", "OC-DOCK-007", "OC-NET-001",
}

CREDENTIAL_CHECK_IDS = {
    "OC-CRED-001", "OC-CRED-002", "OC-CRED-003", "OC-CRED-004",
    "OC-PERM-002",
}

MCP_CHECK_IDS = {
    "OC-MCP-001", "OC-MCP-002", "OC-MCP-003",
    "OC-MCP-004", "OC-MCP-005", "OC-MCP-006",
}

# Tier 1 check IDs (must match models.py TIER1_CHECK_IDS)
TIER1_CHECK_IDS = {
    "OC-SKILL-001", "OC-SKILL-002", "OC-SKILL-003", "OC-SKILL-004",
    "OC-CRED-002", "OC-CRED-004",
    "OC-MCP-001",
    "OC-DOCK-004", "OC-DOCK-006", "OC-NET-001",
    "OC-PERM-002",
    "OC-SOUL-001", "OC-SOUL-007",
}

_NO_CONFIG_NEEDLE = "No config file found"

# Categories that indicate artifact presence
DOCKER_CATEGORIES = {"Docker Sandbox"}
SKILL_CATEGORIES = {"Skill Vetting"}
MCP_CATEGORIES = {"MCP Server", "MCP Server Audit"}
ENV_CATEGORIES = {"Credential Hygiene"}
CONFIG_CATEGORIES = {"Configuration"}
SOUL_CATEGORIES = {"SOUL.md Integrity"}
RUNTIME_CATEGORIES = {"Docker Sandbox", "File Permissions"}

# ---------------------------------------------------------------------------
# Variant type inference
# ---------------------------------------------------------------------------

VARIANT_TYPE_PATTERNS = {
    "docker_deployment": [
        r"docker", r"deploy", r"compose", r"container", r"k8s", r"kubernetes",
    ],
    "platform_port": [
        r"android", r"ios", r"wechat", r"telegram", r"whatsapp", r"discord",
        r"slack", r"termux", r"mobile", r"desktop",
    ],
    "control_plane": [
        r"control.?plane", r"command.?center", r"mission.?control",
        r"dashboard", r"admin", r"monitor", r"orchestrat",
    ],
    "skills_ecosystem": [
        r"skill", r"plugin", r"extension", r"addon", r"add-on",
        r"marketplace", r"hub", r"registry",
    ],
    "regional_localized": [
        r"\bcn\b", r"china", r"chinese", r"\bjp\b", r"japan",
        r"korean", r"\bkr\b", r"locali[sz]", r"i18n",
    ],
    "wrapper_tooling": [
        r"wrapper", r"cli", r"tool", r"util", r"helper", r"sdk",
        r"api", r"library", r"installer", r"setup", r"script",
        r"ctl\b", r"bot\b",
    ],
    "core": [
        r"^openclaw/openclaw$", r"nemoclaw",
    ],
}


def infer_variant_type(full_name: str, description: str) -> str:
    """Infer variant_type from repo name and description."""
    text = f"{full_name} {description or ''}".lower()

    # Core repos
    if re.search(r"^openclaw/openclaw$", full_name, re.IGNORECASE):
        return "core"
    if "nemoclaw" in full_name.lower():
        return "core"

    for vtype, patterns in VARIANT_TYPE_PATTERNS.items():
        if vtype == "core":
            continue
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return vtype

    return "unknown"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def repo_to_folder(repo_name: str) -> str:
    """Convert 'owner/repo' to 'owner-repo' folder name."""
    candidate = repo_name.replace("/", "-")
    if os.path.isdir(os.path.join(BATCH_DIR, candidate)):
        return candidate
    # Case-insensitive fallback
    if os.path.isdir(BATCH_DIR):
        for d in os.listdir(BATCH_DIR):
            if d.lower() == candidate.lower():
                return d
    return candidate


def load_audit_json(folder: str) -> dict | None:
    """Load the JSON audit report for a repo folder."""
    json_path = os.path.join(BATCH_DIR, folder, f"{folder}.json")
    if os.path.exists(json_path):
        with open(json_path) as f:
            return json.load(f)
    # Fallback: find any .json in folder
    folder_path = os.path.join(BATCH_DIR, folder)
    if os.path.isdir(folder_path):
        for fname in os.listdir(folder_path):
            if fname.endswith(".json"):
                with open(os.path.join(folder_path, fname)) as f:
                    return json.load(f)
    return None


def confidence_sort_key(conf: str) -> int:
    """Return sort key for confidence: lower = higher confidence."""
    if conf == "\u2714":
        return 0
    if conf == "\u2796":
        return 1
    return 2


def confidence_to_icon(conf_text: str) -> str:
    """Normalize confidence text to icon."""
    low = conf_text.lower().strip()
    if low in ("high", "\u2714"):
        return "\u2714"
    if low in ("medium", "\u2796"):
        return "\u2796"
    return "\u2753"


# ---------------------------------------------------------------------------
# Per-repo field computation
# ---------------------------------------------------------------------------

def compute_repo_entry(csv_row: dict, audit: dict | None) -> dict:
    """Build one summary object for a repo."""
    full_name = csv_row["full_name"]
    html_url = csv_row["html_url"]
    description = csv_row.get("description", "")
    is_fork = csv_row.get("is_fork", "False").strip().lower() == "true"
    stars = int(csv_row.get("stars", 0) or 0)
    forks = int(csv_row.get("forks", 0) or 0)
    updated_at = csv_row.get("updated_at", "")
    variant_score = int(csv_row.get("score", 0) or 0)

    # --- Recompute scoring from raw findings (not stale scoring block) ---
    findings = []
    if audit:
        findings = audit.get("findings", [])

    tier1_count = 0
    tier2_count = 0
    tier3_count = 0
    has_critical = False
    key_signals_raw: list[str] = []
    observed_artifact_categories: set[str] = set()

    for f in findings:
        fid = f.get("id", "")
        status = f.get("status", "")
        severity = f.get("severity", "")
        detail = f.get("detail", "")

        if status == "SKIP":
            continue

        if severity == "CRITICAL" and status == "FAIL":
            has_critical = True

        if status == "FAIL":
            if fid in TIER1_CHECK_IDS:
                tier1_count += 1
                key_signals_raw.append(f"{fid}: {f.get('title', '')}")
            else:
                tier2_count += 1
                key_signals_raw.append(f"{fid}: {f.get('title', '')}")
            observed_artifact_categories.add(f.get("category", ""))
        elif status == "WARN":
            if _NO_CONFIG_NEEDLE in detail:
                tier3_count += 1
            else:
                tier2_count += 1
                key_signals_raw.append(f"{fid}: {f.get('title', '')}")
                observed_artifact_categories.add(f.get("category", ""))

    exposure_score = (tier1_count * 3) + (tier2_count * 1)

    # Grade
    if exposure_score >= 6 or has_critical:
        grade = "RED"
    elif exposure_score >= 2:
        grade = "YELLOW"
    else:
        grade = "GREEN"

    # Confidence — matches v2 model in models.py
    if tier1_count > 0:
        confidence = "\u2714"
    elif len(observed_artifact_categories) >= 1:
        confidence = "\u2796"
    else:
        confidence = "\u2753"

    key_signals_raw = key_signals_raw[:5]

    # Count by status
    fail_count = sum(1 for f in findings if f.get("status") == "FAIL")
    warn_count = sum(1 for f in findings if f.get("status") == "WARN")
    pass_count = sum(1 for f in findings if f.get("status") == "PASS")
    skip_count = sum(1 for f in findings if f.get("status") == "SKIP")

    # Count by severity (only actionable findings)
    critical_count = sum(1 for f in findings
                         if f.get("severity") == "CRITICAL" and f.get("status") == "FAIL")
    high_count = sum(1 for f in findings
                     if f.get("severity") == "HIGH" and f.get("status") in ("FAIL", "WARN"))
    medium_count = sum(1 for f in findings
                       if f.get("severity") == "MEDIUM" and f.get("status") in ("FAIL", "WARN"))

    # Categories present
    categories_present = list({f.get("category", "") for f in findings
                               if f.get("status") in ("PASS", "FAIL", "WARN")})

    # --- Artifact flags ---
    finding_categories = {f.get("category", "") for f in findings
                          if f.get("status") in ("PASS", "FAIL", "WARN")}
    finding_ids_active = {f.get("id", "") for f in findings
                          if f.get("status") in ("FAIL", "WARN")
                          and _NO_CONFIG_NEEDLE not in f.get("detail", "")}

    has_docker_artifacts = bool(finding_categories & DOCKER_CATEGORIES)
    has_skill_artifacts = bool(finding_categories & SKILL_CATEGORIES)
    has_mcp_artifacts = bool(finding_categories & MCP_CATEGORIES)
    has_env_artifacts = bool(finding_categories & ENV_CATEGORIES)
    has_config_artifacts = bool(finding_categories & CONFIG_CATEGORIES)
    has_soul_artifacts = bool(finding_categories & SOUL_CATEGORIES)
    has_runtime_artifacts = bool(finding_categories & RUNTIME_CATEGORIES)

    # --- Risk flags ---
    has_skill_risk = bool(finding_ids_active & SKILL_CHECK_IDS)
    has_docker_risk = bool(finding_ids_active & DOCKER_CHECK_IDS)
    has_credential_risk = bool(finding_ids_active & CREDENTIAL_CHECK_IDS)
    has_mcp_risk = bool(finding_ids_active & MCP_CHECK_IDS)

    has_observed_findings = (tier1_count > 0 or tier2_count > 0)
    has_config_inference_only = (
        tier1_count == 0
        and tier3_count > 0
        and tier2_count <= 1
        and not has_observed_findings
    )

    # --- Deployability ---
    desc_lower = (description or "").lower()
    has_install_scripts = any(
        kw in desc_lower
        for kw in ("install", "setup", "deploy", "run ", "docker")
    )
    is_likely_deployable = (
        has_docker_artifacts or has_config_artifacts or has_mcp_artifacts
        or has_runtime_artifacts or has_install_scripts
    )

    # --- Low confidence / unknown ---
    is_unknown_or_low_confidence = (
        confidence == "\u2753"
        or (skip_count > len(findings) * 0.5 if findings else True)
    ) and not has_observed_findings

    # --- Variant type ---
    variant_type = infer_variant_type(full_name, description)

    # --- Danger score ---
    danger_score = exposure_score + (critical_count * 2)

    # --- Review score ---
    review_score = 0
    if grade == "YELLOW":
        review_score = exposure_score + tier2_count

    # --- Key signals (max 3, tier1 first then tier2, no config defaults) ---
    key_signals = []
    if key_signals_raw:
        key_signals = [s.split(": ", 1)[-1] if ": " in s else s
                       for s in key_signals_raw[:3]]
    if not key_signals:
        if is_unknown_or_low_confidence:
            if tier3_count > 10:
                key_signals.append("Mostly inferred defaults")
            if not audit:
                key_signals.append("Not yet scanned")
            else:
                key_signals.append("Limited artifacts available")
        elif has_config_inference_only:
            key_signals.append("Config inference only — no observed risk")
        elif grade == "GREEN" and audit:
            key_signals.append("No significant issues found")

    # --- Detail page URL ---
    folder = repo_to_folder(full_name)
    slug = folder.lower()
    detail_page_url = f"rr-repo-{slug}.html"

    return {
        "repo": full_name,
        "html_url": html_url,
        "description": description or "",
        "is_fork": is_fork,
        "stars": stars,
        "forks": forks,
        "updated_at": updated_at,
        "variant_score": variant_score,
        "variant_type": variant_type,
        # Scores (popularity filled in after normalization pass)
        "popularity_score": 0.0,
        "popularity_rank": 0,
        "danger_score": danger_score,
        "danger_rank": 0,
        "review_score": review_score,
        "exposure_score": exposure_score,
        "grade": grade,
        "confidence": confidence,
        # Counts
        "tier1_count": tier1_count,
        "tier2_count": tier2_count,
        "tier3_count": tier3_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "pass_count": pass_count,
        "skip_count": skip_count,
        # Flags
        "is_likely_deployable": is_likely_deployable,
        "is_unknown_or_low_confidence": is_unknown_or_low_confidence,
        "has_skill_risk": has_skill_risk,
        "has_docker_risk": has_docker_risk,
        "has_credential_risk": has_credential_risk,
        "has_mcp_risk": has_mcp_risk,
        "has_observed_findings": has_observed_findings,
        "has_config_inference_only": has_config_inference_only,
        "has_docker_artifacts": has_docker_artifacts,
        "has_skill_artifacts": has_skill_artifacts,
        "has_mcp_artifacts": has_mcp_artifacts,
        "has_env_artifacts": has_env_artifacts,
        "has_config_artifacts": has_config_artifacts,
        "has_soul_artifacts": has_soul_artifacts,
        "has_runtime_artifacts": has_runtime_artifacts,
        # Display
        "categories_present": categories_present,
        "key_signals": key_signals,
        "detail_page_url": detail_page_url,
        # Sorting helpers (for skill/docker/credential views)
        "_skill_fail_count": sum(1 for f in findings
                                 if f.get("id") in SKILL_CHECK_IDS and f.get("status") == "FAIL"),
        "_skill_warn_count": sum(1 for f in findings
                                 if f.get("id") in SKILL_CHECK_IDS and f.get("status") == "WARN"),
        "_docker_fail_count": sum(1 for f in findings
                                  if f.get("id") in DOCKER_CHECK_IDS and f.get("status") == "FAIL"),
        "_cred_fail_count": sum(1 for f in findings
                                if f.get("id") in CREDENTIAL_CHECK_IDS and f.get("status") == "FAIL"),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Read CSV
    if not os.path.exists(CSV_PATH):
        print(f"ERROR: CSV not found at {CSV_PATH}")
        sys.exit(1)

    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        csv_rows = list(reader)

    print(f"Read {len(csv_rows)} repos from CSV")

    # Build entries
    entries = []
    audit_found = 0
    for row in csv_rows:
        folder = repo_to_folder(row["full_name"])
        audit = load_audit_json(folder)
        if audit:
            audit_found += 1
        entry = compute_repo_entry(row, audit)
        entries.append(entry)

    print(f"Matched {audit_found} audit reports out of {len(entries)} repos")

    # --- Popularity score (requires normalization pass) ---
    variant_scores = [e["variant_score"] for e in entries]
    max_vs = max(variant_scores) if variant_scores else 1
    min_vs = min(variant_scores) if variant_scores else 0
    vs_range = max_vs - min_vs if max_vs != min_vs else 1

    for e in entries:
        norm_vs = (e["variant_score"] - min_vs) / vs_range
        e["popularity_score"] = round(
            math.log10(e["stars"] + 1) * 0.70
            + math.log10(e["forks"] + 1) * 0.20
            + norm_vs * 0.10,
            4,
        )

    # --- Assign ranks ---
    # Popularity rank
    by_pop = sorted(entries, key=lambda e: e["popularity_score"], reverse=True)
    for i, e in enumerate(by_pop, 1):
        e["popularity_rank"] = i

    # Danger rank
    by_danger = sorted(entries, key=lambda e: e["danger_score"], reverse=True)
    for i, e in enumerate(by_danger, 1):
        e["danger_rank"] = i

    # --- Write output ---
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(entries)} entries to {OUTPUT_PATH}")

    # Stats
    grades = {}
    for e in entries:
        grades[e["grade"]] = grades.get(e["grade"], 0) + 1
    print(f"Grades: {grades}")
    deployable = sum(1 for e in entries if e["is_likely_deployable"])
    unknown = sum(1 for e in entries if e["is_unknown_or_low_confidence"])
    print(f"Deployable: {deployable}, Unknown/Low-confidence: {unknown}")


if __name__ == "__main__":
    main()
