"""Tests for configuration checks (OC-CFG-*) using vulnerable vs hardened configs."""

from .conftest import scan_fixture


def test_noauth_config_flags_gateway():
    v = scan_fixture("configs/gateway-noauth")
    assert v.failed("OC-CFG-001"), "missing gateway auth not flagged"
    assert v.failed("OC-CFG-002"), "0.0.0.0 bind not flagged"
    assert v.failed("OC-CFG-008"), "elevated tools not flagged"
    assert v.failed("OC-CFG-009"), "open DM policy not flagged"


def test_hardened_config_passes_gateway_checks():
    v = scan_fixture("configs/gateway-hardened")
    cfg_fails = {cid for cid in v.fail_ids if cid.startswith("OC-CFG")}
    assert not cfg_fails, f"hardened config produced CFG fails: {cfg_fails}"


def test_hardened_config_passes_net_egress():
    v = scan_fixture("configs/gateway-hardened")
    assert v.passed("OC-NET-002"), "egress allowlist not recognized"


def test_noauth_config_fails_net_egress():
    v = scan_fixture("configs/gateway-noauth")
    assert v.failed("OC-NET-002")
