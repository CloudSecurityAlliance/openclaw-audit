#!/usr/bin/env python3
"""Build the RiskRubric Agent Repo Leaderboard static site.

Reads:
  - site-data/leaderboard-summary.json  (master summary from build_leaderboard_summary.py)
  - reports/batch_scans/<folder>/*.md    (per-repo markdown reports for detail pages)

Writes:
  - output/riskrubric-site/index.html   (10-view tabbed homepage)
  - output/riskrubric-site/rr-repo-*.html (detail pages)
"""

import base64
import html
import json
import os
import shutil
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUMMARY_JSON = os.path.join(REPO_ROOT, "site-data", "leaderboard-summary.json")
BATCH_DIR = os.path.join(REPO_ROOT, "reports", "batch_scans")
OUTPUT_DIR = os.path.join(REPO_ROOT, "output", "riskrubric-site")
LOGO_DIR = os.path.join(REPO_ROOT, "docs")

CSA_LOGO = os.path.join(LOGO_DIR, "CSA-logo-white.png")
CSAI_LOGO = os.path.join(LOGO_DIR, "csai-logo-full-white.png")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def encode_logo(path):
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        mime = "image/svg+xml" if path.endswith(".svg") else "image/png"
        return f"data:{mime};base64,{data}"
    return ""


def h(text):
    return html.escape(str(text))


def folder_to_slug(folder):
    return folder.lower()


def repo_to_folder(repo_name):
    candidate = repo_name.replace("/", "-")
    if os.path.isdir(os.path.join(BATCH_DIR, candidate)):
        return candidate
    if os.path.isdir(BATCH_DIR):
        for d in os.listdir(BATCH_DIR):
            if d.lower() == candidate.lower():
                return d
    return candidate


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

COMMON_CSS = """
:root {
    --csa-navy: #0B2545;
    --csa-blue: #1B4F9E;
    --csa-orange: #E8792B;
    --csa-light-blue: #4A90D9;
    --csa-white: #FFFFFF;
    --csa-light-gray: #F4F6F9;
    --csa-dark-gray: #2C3E50;
    --csa-green: #27AE60;
    --csa-yellow: #F39C12;
    --csa-red: #E74C3C;
}
*, *::before, *::after { box-sizing: border-box; }
body {
    margin: 0; padding: 0;
    font-family: 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    font-weight: 400; color: var(--csa-dark-gray);
    background: var(--csa-light-gray);
}
a { color: var(--csa-blue); text-decoration: none; }
a:hover { color: var(--csa-light-blue); text-decoration: underline; }
a:focus-visible { outline: 2px solid var(--csa-orange); outline-offset: 2px; }
code, .mono { font-family: 'Fira Code', 'Cascadia Code', Consolas, monospace; }
.site-header {
    background: var(--csa-navy); color: white; padding: 18px 32px;
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 12px;
}
.site-header .logo { height: 40px; }
.header-center { text-align: center; flex: 1; min-width: 200px; }
.header-center h1 { margin: 0; font-size: 1.5rem; font-weight: 700; }
.header-center .subtitle { color: var(--csa-light-blue); font-size: 0.85rem; margin-top: 4px; }
.back-link { display: block; margin-top: 4px; color: var(--csa-light-blue); font-size: 0.85rem; }
.back-link:hover { color: white; }
.site-footer {
    background: var(--csa-light-gray); border-top: 1px solid #ddd;
    padding: 20px 32px; text-align: center; font-size: 0.8rem; color: #666;
}
.site-footer a { color: var(--csa-blue); }
.grade-badge {
    display: inline-block; border-radius: 12px; padding: 4px 12px;
    font-weight: 600; font-size: 0.8rem; color: white; white-space: nowrap;
}
.grade-green { background: var(--csa-green); }
.grade-yellow { background: var(--csa-yellow); }
.grade-red { background: var(--csa-red); }
.content { max-width: 1400px; margin: 0 auto; padding: 24px 32px; }
@media (max-width: 767px) {
    .site-header { padding: 12px 16px; }
    .header-center h1 { font-size: 1.15rem; }
    .content { padding: 16px; }
}
"""

HOMEPAGE_CSS = """
/* Stat cards */
.stat-cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
.stat-card {
    flex: 1; min-width: 130px; background: white; border-radius: 10px;
    padding: 16px; text-align: center;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}
.stat-card .num { font-size: 1.8rem; font-weight: 700; }
.stat-card .label { font-size: 0.8rem; color: #666; margin-top: 4px; }

/* View tabs */
.view-tabs {
    display: flex; gap: 4px; flex-wrap: wrap; margin-bottom: 16px;
    border-bottom: 2px solid #ddd; padding-bottom: 0;
}
.view-tab {
    padding: 8px 16px; border: 1px solid #ddd; border-bottom: none;
    border-radius: 6px 6px 0 0; background: white; cursor: pointer;
    font-size: 0.78rem; font-weight: 600; color: #666;
    transition: all 0.15s;
}
.view-tab:hover { background: #e3ecf7; color: var(--csa-blue); }
.view-tab.active {
    background: var(--csa-navy); color: white; border-color: var(--csa-navy);
}

/* Controls row */
.controls { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin-bottom: 16px; }
.search-box {
    padding: 8px 14px; border: 1px solid #ccc; border-radius: 6px;
    font-size: 0.9rem; width: 260px; max-width: 100%;
}
.search-box:focus { outline: 2px solid var(--csa-blue); border-color: var(--csa-blue); }
.filter-group { display: flex; gap: 4px; align-items: center; }
.filter-group-label { font-size: 0.75rem; color: #666; font-weight: 600; margin-right: 2px; }
.filter-btn {
    padding: 5px 10px; border: 1px solid #ccc; border-radius: 6px;
    background: white; cursor: pointer; font-size: 0.75rem; font-weight: 600;
}
.filter-btn:focus-visible { outline: 2px solid var(--csa-orange); }
.filter-btn.active { background: var(--csa-blue); color: white; border-color: var(--csa-blue); }
.filter-btn[data-grade="green"].active { background: var(--csa-green); border-color: var(--csa-green); }
.filter-btn[data-grade="yellow"].active { background: var(--csa-yellow); border-color: var(--csa-yellow); }
.filter-btn[data-grade="red"].active { background: var(--csa-red); border-color: var(--csa-red); }

/* View description */
.view-desc {
    background: white; border-radius: 8px; padding: 12px 18px; margin-bottom: 16px;
    font-size: 0.85rem; color: #555; box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    border-left: 4px solid var(--csa-orange);
}
.view-desc strong { color: var(--csa-dark-gray); }

/* Table */
.table-wrap { overflow-x: auto; }
table.leaderboard {
    width: 100%; border-collapse: collapse; background: white;
    border-radius: 8px; overflow: hidden;
    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
}
table.leaderboard thead th {
    background: var(--csa-navy); color: white; padding: 10px 12px;
    text-align: left; font-size: 0.75rem; text-transform: uppercase;
    letter-spacing: 0.04em; white-space: nowrap;
}
table.leaderboard tbody tr { cursor: pointer; transition: background 0.15s; }
table.leaderboard tbody tr:nth-child(even) { background: var(--csa-light-gray); }
table.leaderboard tbody tr:hover { background: #e3ecf7; }
table.leaderboard td { padding: 8px 12px; font-size: 0.84rem; vertical-align: middle; }
td.rank { width: 40px; text-align: center; font-weight: 600; color: #999; }
td.repo-name { max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
td.repo-name a { font-weight: 600; }
td.score { font-family: 'Fira Code', Consolas, monospace; text-align: center; }
td.confidence { text-align: center; font-size: 1rem; }
.signal-chip {
    display: inline-block; background: #EBF5FB; color: var(--csa-blue);
    border: 1px solid #AED6F1; border-radius: 4px; padding: 1px 6px;
    font-size: 0.7rem; margin: 1px 2px; white-space: nowrap;
}
.signals-cell { font-size: 0.78rem; max-width: 320px; }
td.num-cell { text-align: center; font-family: 'Fira Code', Consolas, monospace; font-size: 0.82rem; }
.type-badge {
    display: inline-block; background: #f0f0f0; color: #555;
    border-radius: 4px; padding: 2px 8px; font-size: 0.7rem; font-weight: 600;
}
.low-conf-row { opacity: 0.75; }
.result-count { font-size: 0.8rem; color: #666; margin-bottom: 8px; }
.no-results { text-align: center; padding: 40px; color: #999; font-size: 0.9rem; }

@media (max-width: 767px) {
    .view-tabs { gap: 2px; }
    .view-tab { font-size: 0.7rem; padding: 6px 8px; }
    .signals-cell { max-width: 130px; }
    td.repo-name { max-width: 130px; }
}
"""

# ---------------------------------------------------------------------------
# Homepage JS — all 10 views driven client-side from embedded JSON
# ---------------------------------------------------------------------------

HOMEPAGE_JS = r"""
(function() {
    const DATA = window.__LEADERBOARD_DATA__;
    const tbody = document.getElementById('leaderboardBody');
    const searchBox = document.getElementById('searchBox');
    const viewTabs = document.querySelectorAll('.view-tab');
    const viewDescEl = document.getElementById('viewDesc');
    const resultCountEl = document.getElementById('resultCount');

    // Filter state
    let currentView = 'popular';
    let searchQuery = '';
    let gradeFilter = 'all';
    let confidenceFilter = 'all';
    let variantTypeFilter = 'all';

    const CONFIDENCE_ORDER = {'\u2714': 0, '\u2796': 1, '\u2753': 2};
    const GRADE_ORDER = {'RED': 0, 'YELLOW': 1, 'GREEN': 2};

    const VIEW_DESCRIPTIONS = {
        popular: '<strong>Most Popular</strong> — Repos with the highest ecosystem traction (stars, forks, variant score).',
        dangerous: '<strong>Most Dangerous</strong> — Highest-risk repos based on observed findings. Filtered to medium/high confidence by default.',
        high_confidence: '<strong>High Confidence Findings</strong> — The most defensible subset: repos with high-confidence audit results.',
        needs_review: '<strong>Needs Review</strong> — YELLOW-grade repos that warrant closer investigation.',
        variant_type: '<strong>By Variant Type</strong> — Explore risk grouped by repository class (core, docker, platform, etc.).',
        deployable: '<strong>Deployable Systems</strong> — Repos likely closer to real-world deployment (Docker, MCP, install scripts).',
        supply_chain: '<strong>Supply Chain Risk</strong> — Repos where skill/supply-chain behaviors are the primary concern.',
        runtime: '<strong>Runtime / Infrastructure Risk</strong> — Repos with Docker, deployment, or host exposure issues.',
        credential: '<strong>Credential Risk</strong> — Repos with secrets, static credentials, or credential hygiene issues.',
        unknown: '<strong>Low Confidence / Unknown</strong> — Repos needing deeper investigation. Low confidence does NOT mean safe.'
    };

    const VIEW_COLUMNS = {
        popular:         ['rank','repo','grade','confidence','stars','forks','updated','signals'],
        dangerous:       ['rank','repo','grade','confidence','exposure','critical','high','signals'],
        high_confidence: ['rank','repo','grade','exposure','signals'],
        needs_review:    ['rank','repo','confidence','exposure','review_score','signals'],
        variant_type:    ['rank','repo','type','grade','confidence','exposure','signals'],
        deployable:      ['rank','repo','grade','confidence','deploy_flags','signals'],
        supply_chain:    ['rank','repo','grade','confidence','skill_fail','skill_warn','signals'],
        runtime:         ['rank','repo','grade','confidence','docker_fail','danger','signals'],
        credential:      ['rank','repo','grade','confidence','cred_fail','danger','signals'],
        unknown:         ['rank','repo','confidence','grade','signals']
    };

    const COL_HEADERS = {
        rank: '#', repo: 'Repository', grade: 'Grade', confidence: 'Conf',
        stars: 'Stars', forks: 'Forks', updated: 'Updated', signals: 'Key Signals',
        exposure: 'Exposure', critical: 'Crit', high: 'High',
        review_score: 'Review', type: 'Type', deploy_flags: 'Deployability',
        skill_fail: 'Skill FAIL', skill_warn: 'Skill WARN',
        docker_fail: 'Docker FAIL', danger: 'Danger', cred_fail: 'Cred FAIL'
    };

    function debounce(fn, ms) {
        let t; return function() { clearTimeout(t); t = setTimeout(fn, ms); };
    }

    function filterData() {
        let rows = DATA.slice();

        // View-specific pre-filter
        if (currentView === 'dangerous') {
            if (confidenceFilter === 'all') {
                rows = rows.filter(r => r.confidence === '\u2714' || r.confidence === '\u2796');
            }
        }
        if (currentView === 'high_confidence') {
            rows = rows.filter(r => r.confidence === '\u2714');
        }
        if (currentView === 'needs_review') {
            rows = rows.filter(r => r.grade === 'YELLOW');
        }
        if (currentView === 'deployable') {
            rows = rows.filter(r => r.is_likely_deployable);
        }
        if (currentView === 'supply_chain') {
            rows = rows.filter(r => r.has_skill_risk);
        }
        if (currentView === 'runtime') {
            rows = rows.filter(r => r.has_docker_risk || r.has_config_artifacts || r.has_runtime_artifacts);
        }
        if (currentView === 'credential') {
            rows = rows.filter(r => r.has_credential_risk);
        }
        if (currentView === 'unknown') {
            rows = rows.filter(r => r.is_unknown_or_low_confidence);
        }

        // User filters
        if (gradeFilter !== 'all') {
            rows = rows.filter(r => r.grade === gradeFilter);
        }
        if (confidenceFilter !== 'all') {
            rows = rows.filter(r => r.confidence === confidenceFilter);
        }
        if (variantTypeFilter !== 'all') {
            rows = rows.filter(r => r.variant_type === variantTypeFilter);
        }
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            rows = rows.filter(r =>
                r.repo.toLowerCase().includes(q) ||
                (r.description || '').toLowerCase().includes(q) ||
                (r.key_signals || []).join(' ').toLowerCase().includes(q)
            );
        }

        return rows;
    }

    function sortData(rows) {
        const confSort = (a, b) => (CONFIDENCE_ORDER[a.confidence]||2) - (CONFIDENCE_ORDER[b.confidence]||2);
        const gradeSort = (a, b) => (GRADE_ORDER[a.grade]||2) - (GRADE_ORDER[b.grade]||2);

        switch (currentView) {
            case 'popular':
                rows.sort((a,b) => b.popularity_score - a.popularity_score
                    || b.stars - a.stars || b.forks - a.forks);
                break;
            case 'dangerous':
                rows.sort((a,b) => b.danger_score - a.danger_score
                    || b.critical_count - a.critical_count
                    || b.tier1_count - a.tier1_count
                    || b.exposure_score - a.exposure_score);
                break;
            case 'high_confidence':
                rows.sort((a,b) => b.danger_score - a.danger_score
                    || b.popularity_score - a.popularity_score);
                break;
            case 'needs_review':
                rows.sort((a,b) => b.review_score - a.review_score
                    || confSort(a,b)
                    || b.popularity_score - a.popularity_score);
                break;
            case 'variant_type':
                rows.sort((a,b) => b.danger_score - a.danger_score
                    || b.popularity_score - a.popularity_score);
                break;
            case 'deployable':
                rows.sort((a,b) => b.danger_score - a.danger_score
                    || confSort(a,b));
                break;
            case 'supply_chain':
                rows.sort((a,b) => b._skill_fail_count - a._skill_fail_count
                    || b._skill_warn_count - a._skill_warn_count
                    || b.danger_score - a.danger_score
                    || b.popularity_score - a.popularity_score);
                break;
            case 'runtime':
                rows.sort((a,b) => b._docker_fail_count - a._docker_fail_count
                    || b.danger_score - a.danger_score
                    || confSort(a,b));
                break;
            case 'credential':
                rows.sort((a,b) => b._cred_fail_count - a._cred_fail_count
                    || b.danger_score - a.danger_score
                    || b.popularity_score - a.popularity_score);
                break;
            case 'unknown':
                rows.sort((a,b) => b.popularity_score - a.popularity_score);
                break;
        }
        return rows;
    }

    function fmtNum(n) {
        if (n >= 1000) return (n/1000).toFixed(1) + 'k';
        return String(n);
    }

    function fmtDate(s) {
        if (!s) return '—';
        return s.substring(0, 10);
    }

    function renderSignals(signals) {
        if (!signals || !signals.length) return '<span style="color:#999">—</span>';
        return signals.slice(0, 3).map(s =>
            '<span class="signal-chip">' + escapeHtml(s) + '</span>'
        ).join('');
    }

    function escapeHtml(s) {
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    function deployFlags(r) {
        const flags = [];
        if (r.has_docker_artifacts) flags.push('Docker');
        if (r.has_mcp_artifacts) flags.push('MCP');
        if (r.has_config_artifacts) flags.push('Config');
        if (r.has_runtime_artifacts) flags.push('Runtime');
        return flags.length ? flags.map(f => '<span class="signal-chip">' + f + '</span>').join('') : '—';
    }

    function cellValue(r, col) {
        switch (col) {
            case 'rank': return '';  // filled by render
            case 'repo': return '';  // special
            case 'grade': return '<span class="grade-badge grade-' + r.grade.toLowerCase() + '">' + r.grade + '</span>';
            case 'confidence': return r.confidence;
            case 'stars': return fmtNum(r.stars);
            case 'forks': return fmtNum(r.forks);
            case 'updated': return fmtDate(r.updated_at);
            case 'signals': return renderSignals(r.key_signals);
            case 'exposure': return String(r.exposure_score);
            case 'critical': return String(r.critical_count);
            case 'high': return String(r.high_count);
            case 'review_score': return String(r.review_score);
            case 'type': return '<span class="type-badge">' + escapeHtml(r.variant_type.replace(/_/g,' ')) + '</span>';
            case 'deploy_flags': return deployFlags(r);
            case 'skill_fail': return String(r._skill_fail_count);
            case 'skill_warn': return String(r._skill_warn_count);
            case 'docker_fail': return String(r._docker_fail_count);
            case 'danger': return String(r.danger_score);
            case 'cred_fail': return String(r._cred_fail_count);
            default: return '';
        }
    }

    function cellClass(col) {
        if (col === 'rank') return 'rank';
        if (col === 'repo') return 'repo-name';
        if (col === 'confidence') return 'confidence';
        if (['stars','forks','exposure','critical','high','review_score',
             'skill_fail','skill_warn','docker_fail','danger','cred_fail'].includes(col)) return 'num-cell';
        if (col === 'signals' || col === 'deploy_flags') return 'signals-cell';
        return '';
    }

    function render() {
        let rows = filterData();
        rows = sortData(rows);

        const cols = VIEW_COLUMNS[currentView];

        // Update header
        const thead = document.getElementById('leaderboardHead');
        thead.innerHTML = '<tr>' + cols.map(c =>
            '<th scope="col">' + COL_HEADERS[c] + '</th>'
        ).join('') + '</tr>';

        // Update desc
        viewDescEl.innerHTML = VIEW_DESCRIPTIONS[currentView];

        // Update body
        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="' + cols.length + '" class="no-results">No repos match the current filters.</td></tr>';
            resultCountEl.textContent = '0 repos';
            return;
        }

        const MAX_DISPLAY = 100;
        const totalRows = rows.length;
        const displayRows = rows.slice(0, MAX_DISPLAY);
        resultCountEl.textContent = totalRows + ' repo' + (totalRows !== 1 ? 's' : '')
            + (totalRows > MAX_DISPLAY ? ' (showing top ' + MAX_DISPLAY + ')' : '');

        const fragment = document.createDocumentFragment();
        displayRows.forEach((r, idx) => {
            const tr = document.createElement('tr');
            tr.dataset.href = r.detail_page_url;
            if (r.is_unknown_or_low_confidence) tr.classList.add('low-conf-row');

            cols.forEach(col => {
                const td = document.createElement('td');
                const cls = cellClass(col);
                if (cls) td.className = cls;

                if (col === 'rank') {
                    td.textContent = String(idx + 1);
                } else if (col === 'repo') {
                    const a = document.createElement('a');
                    a.href = r.detail_page_url;
                    a.title = r.repo;
                    a.textContent = r.repo;
                    td.appendChild(a);
                } else {
                    td.innerHTML = cellValue(r, col);
                }
                tr.appendChild(td);
            });

            tr.addEventListener('click', function(e) {
                if (e.target.tagName !== 'A') window.location.href = r.detail_page_url;
            });
            fragment.appendChild(tr);
        });

        tbody.innerHTML = '';
        tbody.appendChild(fragment);
    }

    // --- Event handlers ---
    viewTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            viewTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentView = tab.dataset.view;
            render();
        });
    });

    searchBox.addEventListener('input', debounce(function() {
        searchQuery = searchBox.value;
        render();
    }, 200));

    // Grade filter
    document.querySelectorAll('.grade-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.grade-filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            gradeFilter = btn.dataset.grade;
            render();
        });
    });

    // Confidence filter
    document.querySelectorAll('.conf-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.conf-filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            confidenceFilter = btn.dataset.conf;
            render();
        });
    });

    // Variant type filter
    const vtSelect = document.getElementById('variantTypeSelect');
    if (vtSelect) {
        vtSelect.addEventListener('change', () => {
            variantTypeFilter = vtSelect.value;
            render();
        });
    }

    // Initial render
    render();
})();
"""


# ---------------------------------------------------------------------------
# Homepage builder
# ---------------------------------------------------------------------------

def build_homepage(repos_json, csa_logo_uri, csai_logo_uri):
    total = len(repos_json)
    green = sum(1 for r in repos_json if r["grade"] == "GREEN")
    yellow = sum(1 for r in repos_json if r["grade"] == "YELLOW")
    red = sum(1 for r in repos_json if r["grade"] == "RED")
    audited = sum(1 for r in repos_json if r["fail_count"] + r["warn_count"] + r["pass_count"] > 0)
    deployable = sum(1 for r in repos_json if r["is_likely_deployable"])

    # Collect variant types for filter
    vtypes = sorted({r["variant_type"] for r in repos_json})
    vtype_options = '<option value="all">All Types</option>'
    for vt in vtypes:
        label = vt.replace("_", " ").title()
        vtype_options += f'<option value="{h(vt)}">{h(label)}</option>'

    logo_left = f'<a href="https://www.cloudsecurityalliance.org/" target="_blank" rel="noopener"><img src="{csa_logo_uri}" alt="Cloud Security Alliance" class="logo"></a>' if csa_logo_uri else ""
    logo_right = f'<a href="https://csai.foundation/" target="_blank" rel="noopener"><img src="{csai_logo_uri}" alt="CSAI Foundation" class="logo"></a>' if csai_logo_uri else ""

    # Embed JSON data
    data_json = json.dumps(repos_json, ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RiskRubric Agent Repo Leaderboard</title>
<style>{COMMON_CSS}{HOMEPAGE_CSS}</style>
</head>
<body>
<header class="site-header">
  {logo_left}
  <div class="header-center">
    <h1>RiskRubric Agent Repo Leaderboard</h1>
    <div class="subtitle">Powered by <a href="https://github.com/cloudsecurityalliance/openclaw-audit" target="_blank" rel="noopener" style="color:var(--csa-light-blue)">openclaw-audit</a> v1.0.0 — CSAI OpenClaw Hardening Guide Compliance Scanner</div>
  </div>
  {logo_right}
</header>
<main class="content">

  <div class="stat-cards">
    <div class="stat-card"><div class="num" style="color:var(--csa-blue)">{total}</div><div class="label">Total Repos</div></div>
    <div class="stat-card"><div class="num" style="color:var(--csa-navy)">{audited}</div><div class="label">Audited</div></div>
    <div class="stat-card"><div class="num" style="color:var(--csa-red)">{red}</div><div class="label">RED</div></div>
    <div class="stat-card"><div class="num" style="color:var(--csa-yellow)">{yellow}</div><div class="label">YELLOW</div></div>
    <div class="stat-card"><div class="num" style="color:var(--csa-green)">{green}</div><div class="label">GREEN</div></div>
    <div class="stat-card"><div class="num" style="color:var(--csa-blue)">{deployable}</div><div class="label">Deployable</div></div>
  </div>

  <div class="view-tabs" role="tablist" aria-label="Homepage views">
    <button class="view-tab active" data-view="popular" role="tab">Most Popular</button>
    <button class="view-tab" data-view="dangerous" role="tab">Most Dangerous</button>
    <button class="view-tab" data-view="high_confidence" role="tab">High Confidence</button>
    <button class="view-tab" data-view="needs_review" role="tab">Needs Review</button>
    <button class="view-tab" data-view="variant_type" role="tab">By Variant Type</button>
    <button class="view-tab" data-view="deployable" role="tab">Deployable</button>
    <button class="view-tab" data-view="supply_chain" role="tab">Supply Chain</button>
    <button class="view-tab" data-view="runtime" role="tab">Runtime Risk</button>
    <button class="view-tab" data-view="credential" role="tab">Credential Risk</button>
    <button class="view-tab" data-view="unknown" role="tab">Unknown</button>
  </div>

  <div id="viewDesc" class="view-desc"></div>

  <div class="controls">
    <input type="text" id="searchBox" class="search-box" placeholder="Search repos, descriptions, or signals..." aria-label="Search">
    <div class="filter-group">
      <span class="filter-group-label">Grade:</span>
      <button class="filter-btn grade-filter-btn active" data-grade="all">All</button>
      <button class="filter-btn grade-filter-btn" data-grade="RED">Red</button>
      <button class="filter-btn grade-filter-btn" data-grade="YELLOW">Yellow</button>
      <button class="filter-btn grade-filter-btn" data-grade="GREEN">Green</button>
    </div>
    <div class="filter-group">
      <span class="filter-group-label">Confidence:</span>
      <button class="filter-btn conf-filter-btn active" data-conf="all">All</button>
      <button class="filter-btn conf-filter-btn" data-conf="\u2714">\u2714</button>
      <button class="filter-btn conf-filter-btn" data-conf="\u2796">\u2796</button>
      <button class="filter-btn conf-filter-btn" data-conf="\u2753">\u2753</button>
    </div>
    <div class="filter-group">
      <span class="filter-group-label">Type:</span>
      <select id="variantTypeSelect" class="search-box" style="width:160px">{vtype_options}</select>
    </div>
  </div>

  <div id="resultCount" class="result-count"></div>

  <div class="table-wrap">
  <table class="leaderboard">
    <thead id="leaderboardHead"></thead>
    <tbody id="leaderboardBody"></tbody>
  </table>
  </div>
</main>

<footer class="site-footer">
  <p>&copy; 2026 Cloud Security Alliance. All rights reserved.</p>
  <p>Generated by <a href="https://github.com/cloudsecurityalliance/openclaw-audit">openclaw-audit</a> v1.0.0 — CSAI OpenClaw Hardening Guide Compliance Scanner</p>
  <p><a href="https://cloudsecurityalliance.org">cloudsecurityalliance.org</a> | <a href="https://github.com/cloudsecurityalliance/openclaw-audit">GitHub</a></p>
</footer>

<script>
window.__LEADERBOARD_DATA__ = {data_json};
</script>
<script>{HOMEPAGE_JS}</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Report page (preserved from original)
# ---------------------------------------------------------------------------

REPORT_CSS = """
.hero-card {
    background: white; border-radius: 10px; padding: 28px 32px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 28px;
}
.hero-card h2 { margin: 0 0 12px; font-size: 1.5rem; }
.hero-meta { display: flex; gap: 20px; flex-wrap: wrap; align-items: center; font-size: 0.9rem; color: #666; }
.hero-score { font-size: 2rem; font-weight: 700; font-family: 'Fira Code', Consolas, monospace; }
.exec-tables { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 28px; }
.exec-tables table {
    border-collapse: collapse; background: white; border-radius: 8px;
    overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.06);
}
.exec-tables th { background: var(--csa-navy); color: white; padding: 8px 14px; text-align: left; font-size: 0.8rem; }
.exec-tables td { padding: 8px 14px; font-size: 0.85rem; }
.exec-tables tr:nth-child(even) { background: var(--csa-light-gray); }
details.section-group { margin-bottom: 16px; }
details.section-group > summary {
    background: white; padding: 14px 20px; border-radius: 8px;
    cursor: pointer; font-weight: 600; font-size: 1.05rem;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    display: flex; align-items: center; gap: 10px; list-style: none;
}
details.section-group > summary::-webkit-details-marker { display: none; }
details.section-group > summary::before { content: '\\25B6'; font-size: 0.75rem; transition: transform 0.2s; }
details.section-group[open] > summary::before { transform: rotate(90deg); }
details.section-group > summary:focus-visible { outline: 2px solid var(--csa-orange); }
.section-h2 { border-left: 4px solid var(--csa-orange); padding-left: 14px; }
.count-badge {
    background: var(--csa-light-gray); border-radius: 10px; padding: 2px 10px;
    font-size: 0.75rem; color: #666; font-weight: 400;
}
.finding-card {
    background: white; border-radius: 8px; margin: 12px 0 12px 20px;
    padding: 18px 22px; box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    border-left: 4px solid #ccc;
}
.finding-card.sev-red { border-left-color: var(--csa-red); }
.finding-card.sev-yellow { border-left-color: var(--csa-yellow); }
.finding-card.sev-green { border-left-color: var(--csa-green); }
.finding-header { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
.finding-title { font-weight: 700; font-size: 1rem; }
.severity-badge {
    display: inline-block; border-radius: 4px; padding: 2px 8px;
    font-weight: 600; font-size: 0.72rem; color: white; text-transform: uppercase;
}
.severity-critical { background: #8B0000; }
.severity-high { background: #E74C3C; }
.severity-medium { background: #F39C12; }
.severity-low { background: #3498DB; }
.severity-info { background: #95A5A6; }
.status-badge {
    display: inline-block; border-radius: 4px; padding: 2px 8px;
    font-size: 0.72rem; font-weight: 600; border: 1px solid #ccc;
}
.status-fail { background: #fdecea; color: #c0392b; border-color: #e6b0aa; }
.status-warn { background: #fef9e7; color: #b7950b; border-color: #f9e79f; }
.status-pass { background: #eafaf1; color: #1e8449; border-color: #a9dfbf; }
.status-skip { background: #f4f6f9; color: #666; border-color: #ddd; }
.finding-desc { margin: 8px 0; font-size: 0.9rem; line-height: 1.5; }
.evidence-block {
    background: #1e1e2e; color: #cdd6f4; padding: 12px 16px; border-radius: 6px;
    font-family: 'Fira Code', Consolas, monospace; font-size: 0.8rem;
    overflow-x: auto; margin: 8px 0; white-space: pre-wrap; word-break: break-word;
}
.recommendation-box {
    background: #ebf5fb; border-left: 3px solid var(--csa-light-blue);
    padding: 10px 16px; border-radius: 4px; margin: 8px 0; font-size: 0.88rem;
}
.framework-tags { margin-top: 10px; }
.framework-tag {
    display: inline-block; background: #EBF5FB; color: #1B4F9E;
    border: 1px solid #AED6F1; border-radius: 4px; padding: 2px 8px;
    font-size: 0.72rem; margin: 2px;
}
@media (max-width: 767px) {
    .hero-card { padding: 18px; }
    .finding-card { margin-left: 0; padding: 14px; }
}
"""


def parse_report_md(text):
    lines = text.split("\n")
    meta = {}
    sections = []
    current_section = None
    current_finding = None
    exec_summary_lines = []
    in_exec = False
    in_posture = False
    posture_lines = []

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("**Target:**"):
            meta["target"] = stripped.split("`")[1] if "`" in stripped else stripped.split(":**")[1].strip()
        elif stripped.startswith("**Scan Mode:**"):
            meta["scan_mode"] = stripped.replace("**Scan Mode:**", "").strip()
        elif stripped.startswith("**Total Checks:**"):
            meta["total_checks"] = stripped.replace("**Total Checks:**", "").strip()
        elif stripped == "## Executive Summary":
            in_exec = True; in_posture = False; i += 1; continue
        elif "Security Posture" in stripped and stripped.startswith("##"):
            in_exec = False; in_posture = True; i += 1; continue
        elif stripped.startswith("## ") and not stripped.startswith("## Executive") and "Security Posture" not in stripped:
            in_exec = False; in_posture = False
            if current_finding and current_section:
                current_section["findings"].append(current_finding)
                current_finding = None
            section_title = stripped[3:].strip()
            current_section = {"title": section_title, "findings": []}
            sections.append(current_section)
            i += 1; continue
        elif stripped.startswith("### ") and current_section is not None and not in_exec:
            in_exec = False; in_posture = False
            if current_finding:
                current_section["findings"].append(current_finding)
            finding_title = stripped[4:].strip()
            color = "green"
            if "\U0001f534" in finding_title:
                color = "red"
            elif "\U0001f7e1" in finding_title:
                color = "yellow"
            current_finding = {
                "title": finding_title, "color": color,
                "severity": "", "status": "", "description": [],
                "evidence": "", "file": "", "recommendation": "", "frameworks": [],
            }
            i += 1; continue
        elif stripped.startswith("### Severity Breakdown") and in_exec:
            pass
        elif in_exec:
            exec_summary_lines.append(line)
        elif in_posture:
            posture_lines.append(line)
        elif current_finding is not None:
            if stripped.startswith("**Severity:**"):
                current_finding["severity"] = stripped.replace("**Severity:**", "").strip()
            elif stripped.startswith("**Status:**"):
                current_finding["status"] = stripped.replace("**Status:**", "").strip()
            elif stripped.startswith("**Evidence:**"):
                ev = stripped.replace("**Evidence:**", "").strip()
                if ev.startswith("`") and ev.endswith("`"):
                    ev = ev[1:-1]
                current_finding["evidence"] = ev
            elif stripped.startswith("**File:**"):
                current_finding["file"] = stripped.replace("**File:**", "").strip().strip("`")
            elif stripped.startswith("**Recommendation:**"):
                current_finding["recommendation"] = stripped.replace("**Recommendation:**", "").strip()
            elif stripped.startswith("**Framework Mappings:**"):
                j = i + 1
                while j < len(lines) and lines[j].strip().startswith("- "):
                    current_finding["frameworks"].append(lines[j].strip()[2:])
                    j += 1
                i = j - 1
            elif stripped and not stripped.startswith("**") and not stripped.startswith("- ") and not stripped.startswith("|"):
                current_finding["description"].append(stripped)
        i += 1

    if current_finding and current_section:
        current_section["findings"].append(current_finding)

    exec_tables_html = parse_md_tables("\n".join(exec_summary_lines))
    posture_html = parse_md_tables("\n".join(posture_lines))
    return meta, exec_tables_html, posture_html, sections


def parse_md_tables(text):
    lines = text.strip().split("\n")
    result = []
    in_table = False
    table_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("|") and "|" in stripped[1:]:
            if not in_table:
                in_table = True
                table_lines = []
            table_lines.append(stripped)
        else:
            if in_table:
                result.append(render_md_table(table_lines))
                in_table = False
                table_lines = []
            if stripped and not stripped.startswith("#"):
                result.append(f"<p>{h(stripped)}</p>")
    if in_table:
        result.append(render_md_table(table_lines))
    return "\n".join(result)


def render_md_table(lines):
    if len(lines) < 2:
        return ""
    headers = [c.strip() for c in lines[0].split("|")[1:-1]]
    rows = []
    for line in lines[2:]:
        cols = [c.strip() for c in line.split("|")[1:-1]]
        rows.append(cols)
    html_parts = ["<table>", "<thead><tr>"]
    for hdr in headers:
        html_parts.append(f'<th scope="col">{h(hdr)}</th>')
    html_parts.append("</tr></thead><tbody>")
    for row in rows:
        html_parts.append("<tr>")
        for cell in row:
            html_parts.append(f"<td>{h(cell)}</td>")
        html_parts.append("</tr>")
    html_parts.append("</tbody></table>")
    return "\n".join(html_parts)


def render_finding(f):
    sev_lower = f["severity"].lower()
    sev_class = "severity-info"
    if "critical" in sev_lower: sev_class = "severity-critical"
    elif "high" in sev_lower: sev_class = "severity-high"
    elif "medium" in sev_lower: sev_class = "severity-medium"
    elif "low" in sev_lower: sev_class = "severity-low"

    status_lower = f["status"].lower()
    status_class = f"status-{status_lower}" if status_lower in ("fail", "warn", "pass", "skip") else "status-skip"
    desc = " ".join(f["description"])
    evidence_html = f'<div class="evidence-block">{h(f["evidence"])}</div>' if f["evidence"] else ""
    rec_html = f'<div class="recommendation-box"><strong>Recommendation:</strong> {h(f["recommendation"])}</div>' if f["recommendation"] else ""
    fw_html = ""
    if f["frameworks"]:
        tags = "".join(f'<span class="framework-tag">{h(fw)}</span>' for fw in f["frameworks"])
        fw_html = f'<div class="framework-tags">{tags}</div>'

    return f"""<div class="finding-card sev-{f['color']}">
  <div class="finding-header">
    <span class="finding-title">{h(f["title"])}</span>
    <span class="severity-badge {sev_class}">{h(f["severity"])}</span>
    <span class="status-badge {status_class}">{h(f["status"])}</span>
  </div>
  <div class="finding-desc">{h(desc)}</div>
  {evidence_html}
  {rec_html}
  {fw_html}
</div>"""


def build_report_page(repo_info, csa_logo_uri, csai_logo_uri):
    folder = repo_to_folder(repo_info["repo"])
    md_path = os.path.join(BATCH_DIR, folder, folder + ".md")
    if not os.path.exists(md_path):
        folder_path = os.path.join(BATCH_DIR, folder)
        if os.path.isdir(folder_path):
            md_files = [f for f in os.listdir(folder_path) if f.endswith(".md")]
            if md_files:
                md_path = os.path.join(folder_path, md_files[0])
            else:
                return None
        else:
            return None

    with open(md_path) as f:
        md_text = f.read()

    meta, exec_html, posture_html, sections = parse_report_md(md_text)

    grade_lower = repo_info["grade"].lower()
    score = repo_info["exposure_score"]
    confidence = repo_info["confidence"]

    hero = f"""<div class="hero-card">
  <h2>{h(repo_info["repo"])}</h2>
  <div class="hero-meta">
    <span class="grade-badge grade-{grade_lower}">{repo_info["grade"]}</span>
    <span>Exposure Score: <strong class="hero-score">{score}</strong></span>
    <span>{confidence} Confidence</span>
    <span>{h(meta.get("scan_mode", "Source Code Scan"))} | Total Checks: {h(meta.get("total_checks", "?"))}</span>
  </div>
</div>"""

    exec_section = f"""<h2 class="section-h2">Executive Summary</h2>
<div class="exec-tables">{exec_html}</div>"""

    sections_html = []
    for sec in sections:
        count = len(sec["findings"])
        has_fail = any(f["status"].upper() == "FAIL" for f in sec["findings"])
        open_attr = " open" if has_fail else ""
        findings_html = "\n".join(render_finding(f) for f in sec["findings"])
        sections_html.append(f"""<details class="section-group"{open_attr}>
  <summary><span class="section-h2">{h(sec["title"])}</span> <span class="count-badge">{count} finding{"s" if count != 1 else ""}</span></summary>
  {findings_html}
</details>""")

    logo_left = f'<a href="https://www.cloudsecurityalliance.org/" target="_blank" rel="noopener"><img src="{csa_logo_uri}" alt="Cloud Security Alliance" class="logo"></a>' if csa_logo_uri else ""
    logo_right = f'<a href="https://csai.foundation/" target="_blank" rel="noopener"><img src="{csai_logo_uri}" alt="CSAI Foundation" class="logo"></a>' if csai_logo_uri else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{h(repo_info["repo"])} — RiskRubric Audit Report</title>
<style>{COMMON_CSS}{REPORT_CSS}</style>
</head>
<body>
<header class="site-header">
  {logo_left}
  <div class="header-center">
    <h1>RiskRubric Agent Repo Leaderboard</h1>
    <a class="back-link" href="index.html">&larr; Back to Leaderboard</a>
  </div>
  {logo_right}
</header>
<main class="content">
  {hero}
  {exec_section}
  {"".join(sections_html)}
</main>
<footer class="site-footer">
  <p>&copy; 2026 Cloud Security Alliance. All rights reserved.</p>
  <p>Generated by openclaw-audit v1.0.0 — CSAI OpenClaw Hardening Guide Compliance Scanner</p>
  <p><a href="https://cloudsecurityalliance.org">cloudsecurityalliance.org</a></p>
</footer>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("Building RiskRubric site...")

    # Load summary JSON
    if not os.path.exists(SUMMARY_JSON):
        print(f"ERROR: {SUMMARY_JSON} not found. Run build_leaderboard_summary.py first.")
        sys.exit(1)

    with open(SUMMARY_JSON) as f:
        repos = json.load(f)
    print(f"  Loaded {len(repos)} repos from summary JSON")

    # Prepare output dir
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)

    # Logos
    csa_logo_uri = encode_logo(CSA_LOGO)
    csai_logo_uri = encode_logo(CSAI_LOGO)
    if not csa_logo_uri:
        print(f"  WARNING: CSA logo not found at {CSA_LOGO}")
    if not csai_logo_uri:
        print(f"  WARNING: CSAI logo not found at {CSAI_LOGO}")
    for src, dst_name in [(CSA_LOGO, "CSA-logo-white.png"), (CSAI_LOGO, "csai-logo-full-white.png")]:
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(OUTPUT_DIR, dst_name))

    # Build homepage
    homepage_html = build_homepage(repos, csa_logo_uri, csai_logo_uri)
    with open(os.path.join(OUTPUT_DIR, "index.html"), "w") as f:
        f.write(homepage_html)
    print("  \u2713 index.html")

    # Copy summary JSON for external consumers
    shutil.copy2(SUMMARY_JSON, os.path.join(OUTPUT_DIR, "leaderboard-summary.json"))

    # Build individual report pages
    success = 0
    for r in repos:
        page = build_report_page(r, csa_logo_uri, csai_logo_uri)
        if page:
            fname = r["detail_page_url"]
            with open(os.path.join(OUTPUT_DIR, fname), "w") as f:
                f.write(page)
            success += 1

    print(f"  \u2713 {success} report pages")
    total_files = len(os.listdir(OUTPUT_DIR))
    print(f"  Total files in output: {total_files}")
    print(f"  Output: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
