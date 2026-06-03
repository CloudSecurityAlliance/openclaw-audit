"""Tests for correlated attack-path checks (OC-PATH-*)."""

from openclaw_audit.models import EvidenceQuality

from .conftest import scan_fixture


def test_open_dm_elevated_path():
    v = scan_fixture("configs/open-dm-elevated")
    assert v.failed("OC-PATH-001"), "open DM + elevated tools path not detected"


def test_open_dm_elevated_not_triggered_when_isolated():
    """Hardened config has restricted DM + per-channel-peer scope → no path."""
    v = scan_fixture("configs/gateway-hardened")
    assert not v.failed("OC-PATH-001")


def test_public_agent_private_browser_path():
    v = scan_fixture("configs/gateway-noauth")
    assert v.failed("OC-PATH-004"), "public agent + private browser path not detected"


def test_secret_to_egress_path():
    v = scan_fixture("malicious/exfil-skill")
    assert v.failed("OC-PATH-003"), "secret-to-egress path not detected"


def test_no_secret_egress_on_benign():
    v = scan_fixture("benign/normal-skill")
    assert not v.failed("OC-PATH-003")


def test_injection_to_tool_use_path():
    v = scan_fixture("malicious/injection-tool-skill")
    assert v.failed("OC-PATH-002"), "prompt-injection-to-tool-use path not detected"


def test_untrusted_mcp_broad_tools_path():
    v = scan_fixture("mcp/unpinned")
    assert v.failed("OC-PATH-005"), "untrusted MCP path not detected"


def test_remote_code_download_path():
    v = scan_fixture("malicious/download-skill")
    assert v.failed("OC-PATH-006"), "remote-code-download path not detected"


def test_transcript_leak_path():
    v = scan_fixture("malicious/transcript-leak-skill")
    assert v.failed("OC-PATH-007"), "session transcript leakage path not detected"


def test_path_findings_are_correlated_evidence():
    v = scan_fixture("malicious/exfil-skill")
    p3 = [f for f in v.for_check("OC-PATH-003")]
    assert p3
    assert p3[0].evidence_quality == EvidenceQuality.CORRELATED_PATH
    assert p3[0].attack_path  # non-empty attack path label
