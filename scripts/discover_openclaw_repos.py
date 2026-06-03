#!/usr/bin/env python3
"""Discover OpenClaw/NemoClaw repos on GitHub and write openclaw_variants_latest.csv.

Uses 'gh api' (GitHub CLI) for authenticated search. Runs up to 4 queries:
  openclaw in:name
  nemoclaw in:name
  openclaw in:description
  nemoclaw in:description

Deduplicates and assigns a relevance score:
  9 — name contains openclaw or nemoclaw (strong match)
  6 — description contains openclaw or nemoclaw (weaker match)
  3 — matched only via keyword search (low confidence)

Writes: reports/openclaw_variants_latest.csv
"""

import csv
import json
import os
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_CSV = os.path.join(REPO_ROOT, "reports", "openclaw_variants_latest.csv")

SEARCHES = [
    # (query, base_score)
    ("openclaw in:name", 9),
    ("nemoclaw in:name", 9),
    ("openclaw in:description", 6),
    ("nemoclaw in:description", 6),
]

# Max pages per query (100 results/page, GitHub API caps at 10 pages = 1000 results)
MAX_PAGES = 10
PER_PAGE = 100


def gh_search(query: str, page: int) -> list[dict]:
    """Call GitHub search API via gh CLI for one page of results."""
    encoded_q = urllib.parse.quote(query)
    cmd = [
        "gh", "api",
        f"search/repositories?q={encoded_q}&sort=stars&order=desc&per_page={PER_PAGE}&page={page}",
        "--jq", ".items[]"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  WARNING: gh api error: {result.stderr.strip()}", file=sys.stderr)
        return []

    items = []
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if line:
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return items


def score_repo(full_name: str, description: str, base_score: int) -> int:
    """Compute relevance score for a repo."""
    name_lower = full_name.lower()
    desc_lower = (description or "").lower()

    name_match = "openclaw" in name_lower or "nemoclaw" in name_lower
    desc_match = "openclaw" in desc_lower or "nemoclaw" in desc_lower

    if name_match:
        return 9
    if desc_match:
        return base_score  # 6 or 9 depending on query
    return 3  # matched via search but no obvious text match


def main():
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)

    seen: dict[str, dict] = {}  # full_name -> best entry

    for query, base_score in SEARCHES:
        print(f"\nSearching: {query}")
        for page in range(1, MAX_PAGES + 1):
            items = gh_search(query, page)
            if not items:
                print(f"  Page {page}: 0 results — stopping")
                break

            new = 0
            for item in items:
                full_name = item.get("full_name", "")
                if not full_name:
                    continue

                description = item.get("description") or ""
                score = score_repo(full_name, description, base_score)

                if full_name not in seen or seen[full_name]["score"] < score:
                    seen[full_name] = {
                        "full_name": full_name,
                        "html_url": item.get("html_url", f"https://github.com/{full_name}"),
                        "description": description,
                        "is_fork": str(item.get("fork", False)),
                        "stars": item.get("stargazers_count", 0),
                        "forks": item.get("forks_count", 0),
                        "updated_at": item.get("updated_at", ""),
                        "score": score,
                    }
                    new += 1

            print(f"  Page {page}: {len(items)} results, {new} new/updated (total: {len(seen)})")

            if len(items) < PER_PAGE:
                break  # Last page

            # Avoid hammering the API
            time.sleep(0.5)

    # Sort by score desc, then stars desc
    repos = sorted(seen.values(), key=lambda r: (-r["score"], -r["stars"]))

    print(f"\nTotal unique repos found: {len(repos)}")

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "full_name", "html_url", "description",
            "is_fork", "stars", "forks", "updated_at", "score"
        ])
        writer.writeheader()
        writer.writerows(repos)

    print(f"Wrote {len(repos)} repos to {OUTPUT_CSV}")

    # Quick stats
    score_dist = {}
    for r in repos:
        s = r["score"]
        score_dist[s] = score_dist.get(s, 0) + 1
    print(f"Score distribution: {dict(sorted(score_dist.items()))}")


if __name__ == "__main__":
    main()
