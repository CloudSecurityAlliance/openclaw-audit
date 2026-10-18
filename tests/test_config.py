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


def test_openclaw_json_filename_is_parsed():
    """Real installations use ~/.openclaw/openclaw.json; it must be discovered
    and parsed — regression test for silent fail-open on the real config name."""
    v = scan_fixture("instances/openclaw-json")
    assert v.passed("OC-CFG-001"), "token auth in openclaw.json not recognized"
    assert v.failed("OC-CFG-002"), "lan bind in openclaw.json not flagged"
    assert not v.for_check("OC-CFG-000"), \
        "spurious OC-CFG-000 even though a config file exists"


def test_instance_without_config_raises_oc_cfg_000():
    """A config-less installed instance must surface OC-CFG-000 (HIGH) instead
    of only silent default WARNs."""
    v = scan_fixture("instances/no-config")
    assert v.failed("OC-CFG-000"), "config-less instance did not raise OC-CFG-000"
