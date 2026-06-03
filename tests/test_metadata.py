"""Tests for triage metadata (confidence, evidence quality, exploitability, blast radius)."""

import json

from openclaw_audit.models import (
    BlastRadius, Confidence, EvidenceQuality, Exploitability, Status,
    derive_finding_metadata,
)
from openclaw_audit.reports import json_out, sarif
from openclaw_audit.scanner import scan

from .conftest import FIXTURES, scan_fixture


def test_all_findings_get_metadata():
    v = scan_fixture("configs/gateway-noauth")
    for f in v.findings:
        assert f.confidence is not None, f"{f.check_id} missing confidence"
        assert f.evidence_quality is not None, f"{f.check_id} missing evidence_quality"
        assert f.exploitability is not None, f"{f.check_id} missing exploitability"
        assert f.blast_radius is not None, f"{f.check_id} missing blast_radius"


def test_pattern_checks_are_medium_confidence():
    """Skill regex findings are pattern matches → medium confidence."""
    conf, eq, _, _ = derive_finding_metadata("OC-SKILL-001", None, Status.FAIL)
    assert eq == EvidenceQuality.PATTERN_MATCH
    assert conf == Confidence.MEDIUM


def test_config_checks_are_high_confidence():
    conf, eq, _, _ = derive_finding_metadata("OC-CFG-001", None, Status.FAIL)
    assert eq == EvidenceQuality.CONFIG_VALUE
    assert conf == Confidence.HIGH


def test_correlated_paths_are_demonstrated():
    conf, eq, exp, _ = derive_finding_metadata("OC-PATH-003", None, Status.FAIL)
    assert eq == EvidenceQuality.CORRELATED_PATH
    assert conf == Confidence.HIGH
    assert exp == Exploitability.DEMONSTRATED


def test_credential_theft_blast_radius_is_cloud():
    _, _, _, blast = derive_finding_metadata("OC-SKILL-006", None, Status.FAIL)
    assert blast == BlastRadius.CLOUD_ACCOUNT


def test_warn_is_theoretical():
    _, _, exp, _ = derive_finding_metadata("OC-CFG-007", None, Status.WARN)
    assert exp == Exploitability.THEORETICAL


def test_metadata_in_json_output():
    report = scan(target=FIXTURES / "malicious/injection-skill")
    data = json.loads(json_out.render(report, None))
    inj = [f for f in data["findings"] if f["id"] == "OC-SKILL-001" and f["status"] == "FAIL"]
    assert inj, "injection finding missing from JSON"
    assert inj[0]["confidence"] == "medium"
    assert inj[0]["evidence_quality"] == "pattern_match"


def test_metadata_in_sarif_output():
    report = scan(target=FIXTURES / "configs/gateway-noauth")
    data = json.loads(sarif.render(report, None))
    results = data["runs"][0]["results"]
    cfg001 = [r for r in results if r["ruleId"] == "OC-CFG-001"]
    assert cfg001
    assert cfg001[0]["properties"].get("confidence") == "high"
    assert cfg001[0]["properties"].get("blast_radius") == "host"
