"""Tests for the capability model."""

import json

from openclaw_audit import capabilities as cap
from openclaw_audit.capabilities import build_profiles
from openclaw_audit.context import detect_context
from openclaw_audit.reports import json_out
from openclaw_audit.scanner import scan

from .conftest import FIXTURES


def _profiles(fixture: str):
    ctx = detect_context(FIXTURES / fixture)
    return build_profiles(ctx)


def test_exfil_skill_has_secret_read_and_egress():
    profiles = _profiles("malicious/exfil-skill")
    skill = next(p for p in profiles if p.asset_type == "skill")
    assert skill.reads_secrets(), "secret read capability not detected"
    assert skill.has_egress(), "egress capability not detected"
    assert cap.NETWORK_POST in skill.capabilities
    assert cap.SSH_KEY_READ in skill.capabilities or cap.CREDENTIAL_READ in skill.capabilities


def test_exfil_skill_risk_path():
    profiles = _profiles("malicious/exfil-skill")
    skill = next(p for p in profiles if p.asset_type == "skill")
    assert "sensitive_source -> network_egress" in skill.risk_paths


def test_benign_skill_no_secret_egress_path():
    profiles = _profiles("benign/normal-skill")
    skill = next(p for p in profiles if p.asset_type == "skill")
    assert "sensitive_source -> network_egress" not in skill.risk_paths


def test_mcp_profile_marked_public():
    profiles = _profiles("mcp/unpinned")
    mcp = next(p for p in profiles if p.asset_type == "mcp_server")
    assert mcp.trust_boundary == "public_mcp"
    assert cap.MCP_TOOL_CALL in mcp.capabilities


def test_download_skill_remote_code_capability():
    profiles = _profiles("malicious/download-skill")
    skill = next(p for p in profiles if p.asset_type == "skill")
    assert cap.REMOTE_CODE_DOWNLOAD in skill.capabilities
    assert "remote_download -> execution" in skill.risk_paths


def test_paste_sink_detection():
    profiles = _profiles("malicious/download-skill")
    skill = next(p for p in profiles if p.asset_type == "skill")
    # vercel.app payload host counts as a paste/exfil sink
    assert cap.has_paste_sink(skill)


def test_capability_profiles_in_json():
    report = scan(target=FIXTURES / "malicious/exfil-skill")
    data = json.loads(json_out.render(report, None))
    assert "capability_profiles" in data
    assert any(p["asset_type"] == "skill" for p in data["capability_profiles"])
