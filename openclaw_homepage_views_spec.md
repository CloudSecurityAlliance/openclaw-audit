# OpenClaw Audit Homepage Views & Sorting Specification (v1)

## Objective

Enhance the OpenClaw-audit project so the leaderboard site can generate and display **10 homepage views / sorting criteria** using:

1. the variant discovery CSV (currently containing repo metadata such as `full_name`, `html_url`, `description`, `is_fork`, `stars`, `forks`, `updated_at`, `score`, `reasons`)
2. the per-repo audit markdown or structured report output
3. the existing scoring rubric for:
   - **Exposure Score**
   - **Grade** (`RED`, `YELLOW`, `GREEN`)
   - **Confidence** (`✔`, `➖`, `❓`)

The goal is to support a larger homepage (for example 100 repos) with multiple useful ways to explore the dataset, not just a single popularity-ranked list.

---

# Guiding Principle

The homepage should behave like a **lens into the OpenClaw ecosystem**, not just a static list.

Each view should answer a different question:

- Which repos matter the most?
- Which repos look the riskiest?
- Which findings are high-confidence?
- Which repos are likely deployable?
- Where is the risk concentrated (skills, Docker, credentials, MCP, etc.)?
- Which repos remain largely unknown because repo-only scanning is incomplete?

---

# Data Inputs

## Input A — Variant Discovery CSV

The current CSV contains at least these fields:

- `full_name`
- `html_url`
- `description`
- `is_fork`
- `stars`
- `forks`
- `updated_at`
- `score`
- `reasons`

These MUST remain available in the site build pipeline.

## Input B — Audit Summary Data

For each repo, the site build MUST ingest or generate a normalized summary object containing at least:

- `repo`
- `exposure_score`
- `grade`
- `confidence`
- `tier1_count`
- `tier2_count`
- `tier3_count`
- `fail_count`
- `warn_count`
- `pass_count`
- `skip_count`
- `critical_count`
- `high_count`
- `medium_count`
- `categories_present`
- `artifact_flags`
- `key_signals`
- `detail_page_url`

If the current audit pipeline does not already emit these fields in a machine-readable format, add a summary JSON for each repo and/or a master summary JSON file.

---

# Required Computed Fields

Add the following computed fields to the summary pipeline.

## 1. Popularity Score

This supports the “Most Popular” view.

Use a simple normalized composite:

```text
popularity_score =
    log10(stars + 1) * 0.70 +
    log10(forks + 1) * 0.20 +
    normalized_variant_score * 0.10
```

Where:
- `normalized_variant_score` = normalize `score` from the discovery CSV to a 0–1 range within the current dataset

Notes:
- Keep the raw `stars` and `forks`
- Also store `popularity_rank`

---

## 2. Danger Score

This supports the “Most Dangerous” view.

Use:

```text
danger_score =
    exposure_score
    + (critical_count * 2)
```

Notes:
- Do **not** multiply by confidence
- Confidence is displayed separately
- This score is only for ordering

Also store:
- `danger_rank`

---

## 3. Review Score

This supports the “Needs Review” view.

Goal:
Surface repos that are not clearly `RED`, but are not safely dismissible either.

Use:

```text
review_score =
    0 if grade != "YELLOW"
    else exposure_score + tier2_count
```

Only YELLOW repos should appear in this view by default.

---

## 4. Artifact Flags

Generate booleans:

- `has_docker_artifacts`
- `has_skill_artifacts`
- `has_mcp_artifacts`
- `has_env_artifacts`
- `has_config_artifacts`
- `has_soul_artifacts`
- `has_runtime_artifacts`

Set these based on scan evidence, file discovery, or findings.

Examples:
- Docker findings present -> `has_docker_artifacts = true`
- SKILL findings or skills directory discovered -> `has_skill_artifacts = true`
- MCP findings or `.mcp.json` discovered -> `has_mcp_artifacts = true`
- `.env` findings -> `has_env_artifacts = true`

---

## 5. Variant Type

Each repo should have a single `variant_type` field.

Allowed initial values:

- `core`
- `docker_deployment`
- `platform_port`
- `control_plane`
- `skills_ecosystem`
- `regional_localized`
- `wrapper_tooling`
- `unknown`

Use the manually assigned category when available. If not available, infer from repo metadata and findings.

---

## 6. Key Risk Flags

Generate boolean flags for major risk surfaces:

- `has_skill_risk`
- `has_docker_risk`
- `has_credential_risk`
- `has_mcp_risk`
- `has_config_inference_only`
- `has_observed_findings`

Definitions:

### `has_skill_risk`
True if any of:
- OC-SKILL-001 through OC-SKILL-006 present as WARN or FAIL

### `has_docker_risk`
True if any of:
- OC-DOCK-001 through OC-DOCK-007
- OC-NET-001

### `has_credential_risk`
True if any of:
- OC-CRED-001 through OC-CRED-004
- OC-PERM-002

### `has_mcp_risk`
True if any of:
- OC-MCP-001 through OC-MCP-006

### `has_config_inference_only`
True if:
- most risk comes from Tier 3 findings
- and there are no Tier 1 findings
- and there are few or no observed artifacts

### `has_observed_findings`
True if there are Tier 1 or Tier 2 findings that are not Tier 3 default-inference warnings

---

## 7. Deployability Flag

Generate:

- `is_likely_deployable`

Set to `true` if any of:
- `has_docker_artifacts`
- `has_config_artifacts`
- `has_mcp_artifacts`
- install scripts detected
- runtime or deployment files are present

This supports the “Deployable Systems” view.

---

## 8. Unknown / Low-Confidence Flag

Generate:

- `is_unknown_or_low_confidence`

Set to `true` if:
- confidence == `❓`
OR
- skip_count is high
AND
- no meaningful observed findings exist

This supports the “Low Confidence / Unknown” view.

---

# The 10 Required Homepage Views

Implement the following 10 views.

Each view must be accessible through the site UI and generated from the master summary data.

---

## View 1 — Most Popular

### Purpose
Show the repos with the highest ecosystem traction.

### Filter
- none by default

### Sort
1. `popularity_score` descending
2. `stars` descending
3. `forks` descending
4. `updated_at` descending

### Display
Show:
- repo
- grade
- confidence
- stars
- forks
- last updated
- short key signals

---

## View 2 — Most Dangerous

### Purpose
Show the highest-risk repos based on observed findings.

### Default Filter
- confidence in (`✔`, `➖`)

### Sort
1. `danger_score` descending
2. `critical_count` descending
3. `tier1_count` descending
4. `exposure_score` descending

### Display
Show:
- repo
- grade
- confidence
- exposure score
- critical/high finding counts
- short key signals

---

## View 3 — High Confidence Findings

### Purpose
Show the most defensible subset of the data.

### Filter
- confidence == `✔`

### Sort
1. `danger_score` descending
2. `popularity_score` descending

### Display
Show:
- repo
- grade
- exposure score
- key evidence summary

---

## View 4 — Needs Review

### Purpose
Surface repos that are not clearly the worst, but may be important review targets.

### Filter
- grade == `YELLOW`

### Sort
1. `review_score` descending
2. `confidence` (`✔` before `➖` before `❓`)
3. `popularity_score` descending

### Display
Show:
- repo
- confidence
- exposure score
- top 2 reasons it is YELLOW

---

## View 5 — By Variant Type

### Purpose
Allow users to explore risk by repo class.

### UI
Provide a filter control with:
- All
- Core
- Docker / Deployment
- Platform / Edge
- Control Plane
- Skills Ecosystem
- Regional / Localized
- Wrapper / Tooling
- Unknown

### Default Sort
1. `danger_score` descending
2. `popularity_score` descending

### Display
Show:
- repo
- type
- grade
- confidence
- exposure score

---

## View 6 — Deployable Systems

### Purpose
Focus on repos that are likely closer to real-world deployment.

### Filter
- `is_likely_deployable == true`

### Sort
1. `danger_score` descending
2. `confidence` (`✔` before `➖` before `❓`)
3. `updated_at` descending

### Display
Show:
- repo
- grade
- confidence
- deployability indicators
- key signals

---

## View 7 — Supply Chain Risk

### Purpose
Surface repos where skills / supply-chain behaviors are the main issue.

### Filter
- `has_skill_risk == true`

### Sort
1. count of SKILL FAIL findings descending
2. count of SKILL WARN findings descending
3. `danger_score` descending
4. `popularity_score` descending

### Display
Show:
- repo
- grade
- confidence
- list or summary of skill findings
- number of skill failures

---

## View 8 — Runtime / Infrastructure Risk

### Purpose
Show repos with Docker / deployment / host exposure issues.

### Filter
- `has_docker_risk == true`
OR `has_config_artifacts == true`
OR `has_runtime_artifacts == true`

### Sort
1. Docker FAIL count descending
2. `danger_score` descending
3. `confidence` (`✔` first)

### Display
Show:
- repo
- grade
- confidence
- Docker / runtime findings summary

---

## View 9 — Credential Risk

### Purpose
Show repos with secrets, static credentials, or credential hygiene issues.

### Filter
- `has_credential_risk == true`

### Sort
1. credential FAIL count descending
2. `danger_score` descending
3. `popularity_score` descending

### Display
Show:
- repo
- grade
- confidence
- credential findings summary

---

## View 10 — Low Confidence / Unknown

### Purpose
Show repos that need deeper investigation because repo-only scan evidence is limited.

### Filter
- `is_unknown_or_low_confidence == true`

### Sort
1. `popularity_score` descending
2. `updated_at` descending

### Display
Show:
- repo
- confidence
- grade
- short explanation such as:
  - “Mostly inferred defaults”
  - “Limited artifacts available”
  - “Repo-only scan incomplete”

This view is important because it helps communicate that:
- repo scanning is an early phase
- ongoing and deployment-level scanning remains necessary

---

# Required UI Controls

Add these homepage controls.

## A. View Selector
A primary control to switch among the 10 views.

## B. Search Box
Search by:
- repo name
- description
- key signals

## C. Confidence Filter
Allow:
- All
- ✔ only
- ✔ + ➖
- ❓ only

## D. Grade Filter
Allow:
- All
- RED
- YELLOW
- GREEN

## E. Variant Type Filter
Allow filtering by `variant_type`

## F. Artifact Filter
Optional but recommended:
- Has Docker
- Has Skills
- Has MCP
- Has Credentials
- Deployable only

---

# Master Summary Output

Generate a machine-readable summary file for the site build.

## Required filename

```text
site-data/leaderboard-summary.json
```

## Required structure

An array of repo summary objects, one per repo.

Each object should include at least:

- `repo`
- `html_url`
- `description`
- `stars`
- `forks`
- `updated_at`
- `variant_score`
- `popularity_score`
- `popularity_rank`
- `danger_score`
- `danger_rank`
- `exposure_score`
- `grade`
- `confidence`
- `variant_type`
- `is_likely_deployable`
- `is_unknown_or_low_confidence`
- `has_skill_risk`
- `has_docker_risk`
- `has_credential_risk`
- `has_mcp_risk`
- `has_observed_findings`
- `has_config_inference_only`
- `tier1_count`
- `tier2_count`
- `tier3_count`
- `critical_count`
- `high_count`
- `medium_count`
- `fail_count`
- `warn_count`
- `pass_count`
- `skip_count`
- `key_signals`
- `detail_page_url`

---

# Key Signal Generation

Generate 2–3 concise phrases for each repo.

Examples:
- `Malicious skill patterns detected`
- `Privileged Docker + host networking`
- `Static credentials in .env`
- `MCP authentication missing`
- `Mostly inferred defaults`
- `Limited artifacts available`

Guidelines:
- Prefer observed findings over inferred ones
- If no strong findings exist, say why confidence is low
- Keep each signal short enough for a homepage card or table row

---

# Sorting / Filtering Implementation Notes

## Confidence ordering
Use this order when sorting:
1. `✔`
2. `➖`
3. `❓`

## Grade ordering
Use this order when sorting:
1. `RED`
2. `YELLOW`
3. `GREEN`

## Date ordering
Use `updated_at` descending for “recently active” tie-breaks

---

# Important Rules

## Rule 1
Do not let Tier 3 inferred-default findings dominate homepage views.

## Rule 2
Views focused on “danger” should favor observed evidence and moderate/high confidence.

## Rule 3
Views focused on “unknown” should explicitly explain that low confidence is not the same as safe.

## Rule 4
Keep the site understandable at a glance:
- grade
- confidence
- one or two strong signals
- click-through for full detail

---

# Recommended Initial Homepage Tabs

For the first production pass, expose these tabs in the UI:

1. Most Popular
2. Most Dangerous
3. High Confidence
4. Needs Review
5. By Variant Type
6. Deployable Systems
7. Supply Chain Risk
8. Runtime Risk
9. Credential Risk
10. Unknown / Low Confidence

---

# Success Criteria

The enhancement is complete when:

1. The system produces all required computed fields
2. The site supports the 10 views above
3. Each repo card or row shows:
   - repo name
   - grade
   - confidence icon
   - score
   - key signals
4. Clicking a repo still opens the detailed report page
5. Low-confidence results are visually and semantically distinct from strong positive findings

---

