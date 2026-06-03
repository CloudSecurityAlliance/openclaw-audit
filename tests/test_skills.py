"""Tests for skill vetting checks (OC-SKILL-*).

These lock in the key accuracy guarantees: benign skills (including ones that
use ordinary words like "important") must not be flagged, while skills with
prompt injection, download-and-run instructions, and credential access must be.
"""

from openclaw_audit.models import Status

from .conftest import scan_fixture


# --- False-positive regression: benign skills must not be flagged ---

def test_normal_skill_no_injection():
    v = scan_fixture("benign/normal-skill")
    assert not v.failed("OC-SKILL-001"), "benign skill flagged as injection"


def test_important_word_not_flagged_as_injection():
    """The word 'important' / 'IMPORTANT:' in ordinary docs must not trip
    OC-SKILL-001 — only the <IMPORTANT> tag and explicit override language do."""
    v = scan_fixture("benign/important-word-skill")
    assert not v.failed("OC-SKILL-001")
    assert not v.failed("OC-SKILL-002")
    assert not v.failed("OC-SKILL-006")


def test_benign_skills_have_no_skill_fails():
    for name in ("benign/normal-skill", "benign/important-word-skill"):
        v = scan_fixture(name)
        skill_fails = {cid for cid in v.fail_ids if cid.startswith("OC-SKILL")}
        assert not skill_fails, f"{name} produced unexpected skill fails: {skill_fails}"


# --- True-positive detection: malicious skills must be flagged ---

def test_injection_skill_detected():
    v = scan_fixture("malicious/injection-skill")
    assert v.failed("OC-SKILL-001"), "prompt injection not detected"


def test_download_and_run_detected():
    v = scan_fixture("malicious/download-skill")
    assert v.failed("OC-SKILL-002"), "download-and-run pattern not detected"


def test_credential_access_detected():
    v = scan_fixture("malicious/exfil-skill")
    assert v.failed("OC-SKILL-006"), "credential access not detected"


def test_network_egress_warned():
    """The exfil skill posts to a remote host — OC-SKILL-005 should warn."""
    v = scan_fixture("malicious/exfil-skill")
    assert v.has_status("OC-SKILL-005", Status.WARN) or v.failed("OC-SKILL-005")
