"""Accuracy report over the fixture corpus.

Each fixture declares the check IDs it is *expected* to FAIL on. From that we
compute true positives, false negatives, and (for benign fixtures) false
positives. Run `pytest -s tests/test_accuracy.py` to print the report.
"""

from openclaw_audit.models import Status

from .conftest import scan_fixture

# fixture -> set of check IDs that SHOULD fail. Benign fixtures map to an
# empty set for their own family (no skill/mcp/docker fails expected).
EXPECTED_FAILS = {
    "benign/normal-skill": set(),
    "benign/important-word-skill": set(),
    "malicious/injection-skill": {"OC-SKILL-001"},
    "malicious/download-skill": {"OC-SKILL-002", "OC-PATH-006"},
    "malicious/exfil-skill": {"OC-SKILL-006", "OC-PATH-003"},
    "malicious/injection-tool-skill": {"OC-SKILL-001", "OC-PATH-002"},
    "malicious/transcript-leak-skill": {"OC-PATH-007"},
    "mcp/unpinned": {"OC-MCP-002", "OC-MCP-005", "OC-PATH-005"},
    "mcp/pinned": set(),
    "mcp/injection-desc": {"OC-MCP-004"},
    "docker/privileged": {"OC-DOCK-004", "OC-DOCK-006", "OC-NET-001"},
    "docker/hardened": set(),
    "configs/gateway-noauth": {
        "OC-CFG-001", "OC-CFG-002", "OC-CFG-008", "OC-CFG-009",
        "OC-PATH-001", "OC-PATH-004",
    },
    "configs/open-dm-elevated": {"OC-PATH-001"},
    "configs/gateway-hardened": set(),
}

# Families a fixture is "about" — used to scope false-positive counting so that
# unrelated noisy checks (e.g. instance defaults) don't pollute FP metrics.
FAMILY_PREFIX = {
    "benign": "OC-SKILL",
    "malicious": "OC-SKILL",
    "mcp": "OC-MCP",
    "docker": "OC-DOCK",
    "configs": "OC-CFG",
}


def _family(fixture: str) -> str:
    top = fixture.split("/", 1)[0]
    return FAMILY_PREFIX[top]


def compute_accuracy():
    """TP/FN are measured against the explicit expectations across all checks.

    False positives are only meaningful for benign/hardened fixtures (those
    with no expected fails): any *in-family* fail there is a true false
    positive. Intentionally-vulnerable fixtures legitimately fail many more
    checks than we enumerate, so extra fails there are not counted as FP.
    """
    tp = fp = fn = 0
    rows = []
    for fixture, expected in EXPECTED_FAILS.items():
        v = scan_fixture(fixture)
        fails = v.fail_ids

        f_tp = len(expected & fails)
        f_fn = len(expected - fails)
        if expected:
            f_fp = 0  # vulnerable fixture: extra in-family fails are legitimate
        else:
            # Benign/hardened: any in-family fail OR any correlated attack-path
            # fail is a false positive (attack paths must never fire here).
            fam = _family(fixture)
            f_fp = len({cid for cid in fails
                        if cid.startswith(fam) or cid.startswith("OC-PATH")})

        tp += f_tp
        fn += f_fn
        fp += f_fp
        rows.append((fixture, f_tp, f_fp, f_fn))
    return tp, fp, fn, rows


def test_accuracy_report(capsys):
    tp, fp, fn, rows = compute_accuracy()
    with capsys.disabled():
        print("\n\n=== Fixture Accuracy Report ===")
        print(f"{'fixture':40s} {'TP':>3} {'FP':>3} {'FN':>3}")
        for fixture, t, p, n in rows:
            print(f"{fixture:40s} {t:>3} {p:>3} {n:>3}")
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        print(f"\nTotals: TP={tp} FP={fp} FN={fn}")
        print(f"Precision={precision:.2%}  Recall={recall:.2%}")

    # No false positives and no false negatives across the corpus.
    assert fp == 0, "fixture corpus produced false positives"
    assert fn == 0, "fixture corpus produced false negatives"
