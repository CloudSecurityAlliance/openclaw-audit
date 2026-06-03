"""Tests for policy-as-code and profile gating."""

import json

import pytest

from openclaw_audit.models import Profile, ScanMode, Status
from openclaw_audit.policy import (
    PolicyError, evaluate, find_policy, load_policy,
)
from openclaw_audit.scanner import scan

from .conftest import FIXTURES


# --- Profiles ---

def test_profile_scan_modes():
    assert Profile.UPSTREAM_REPO.scan_mode == ScanMode.REPO_ONLY
    assert Profile.IMPLEMENTATION_REPO.scan_mode == ScanMode.REPO_ONLY
    assert Profile.LOCAL_INSTANCE.scan_mode == ScanMode.INSTANCE_ONLY
    assert Profile.ENTERPRISE_FLEET.scan_mode == ScanMode.INSTANCE_ONLY
    assert Profile.CI_PR_GATE.scan_mode == ScanMode.REPO_ONLY


def test_ci_profile_gates_on_critical_high():
    sev = Profile.CI_PR_GATE.gate_severities
    assert sev and Profile.UPSTREAM_REPO.gate_severities == frozenset()


def test_findings_carry_profile_applicability():
    report = scan(target=FIXTURES / "configs/gateway-noauth")
    cfg = [f for f in report.findings if f.check_id == "OC-CFG-001"][0]
    assert cfg.profile_applicability in ("repo_only", "instance_only", "both")


# --- Policy loading / validation ---

def _write(tmp_path, obj):
    p = tmp_path / "openclaw-audit.policy.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def test_load_valid_policy(tmp_path):
    p = _write(tmp_path, {
        "profile": "enterprise-production",
        "ci_gate": {"fail_on": ["critical", "high"]},
        "risk_acceptance": {"max_critical": 0},
    })
    pol = load_policy(p)
    assert pol.max_critical == 0
    assert pol.has_gate


def test_accepted_risk_requires_justification(tmp_path):
    p = _write(tmp_path, {"accepted_risks": [{"check": "OC-CFG-003"}]})
    with pytest.raises(PolicyError):
        load_policy(p)


def test_unknown_severity_rejected(tmp_path):
    p = _write(tmp_path, {"ci_gate": {"fail_on": ["catastrophic"]}})
    with pytest.raises(PolicyError):
        load_policy(p)


def test_find_policy_discovers_file(tmp_path):
    _write(tmp_path, {"ci_gate": {"fail_on": ["critical"]}})
    assert find_policy(tmp_path) is not None


# --- Policy evaluation ---

def test_gate_fails_on_critical():
    report = scan(target=FIXTURES / "configs/gateway-noauth")
    from openclaw_audit.policy import Policy
    from openclaw_audit.models import Severity
    pol = Policy(fail_on=frozenset({Severity.CRITICAL}))
    result = evaluate(report, pol)
    assert not result.gate_passed
    assert result.violations


def test_accepted_risk_downgrades_and_clears_gate(tmp_path):
    # Accept every critical/high config check the no-auth fixture trips, so the
    # gate passes and those findings are marked accepted.
    report = scan(target=FIXTURES / "configs/gateway-noauth")
    crit_high = sorted({
        f.check_id for f in report.findings
        if f.status == Status.FAIL and f.severity.value in ("CRITICAL", "HIGH")
    })
    p = _write(tmp_path, {
        "ci_gate": {"fail_on": ["critical", "high"]},
        "accepted_risks": [
            {"check": cid, "justification": "accepted for test"} for cid in crit_high
        ],
    })
    pol = load_policy(p)
    result = evaluate(report, pol)
    assert result.gate_passed
    assert result.accepted_count >= len(crit_high)
    accepted = [f for f in report.findings if f.policy_status == "accepted"]
    assert accepted


def test_yaml_policy_loads_when_pyyaml_present(tmp_path):
    pytest.importorskip("yaml")
    p = tmp_path / "openclaw-audit.policy.yaml"
    p.write_text("ci_gate:\n  fail_on: [critical]\n", encoding="utf-8")
    pol = load_policy(p)
    from openclaw_audit.models import Severity
    assert Severity.CRITICAL in pol.fail_on


def test_required_control_violation():
    report = scan(target=FIXTURES / "configs/gateway-noauth")
    from openclaw_audit.policy import Policy
    pol = Policy(required_controls=["OC-CFG-001"])  # this fails in the fixture
    result = evaluate(report, pol)
    assert not result.gate_passed
    assert any("OC-CFG-001" in v for v in result.violations)
