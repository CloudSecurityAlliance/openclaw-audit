"""Scanner orchestration and report-rendering smoke tests."""

import json

from openclaw_audit.models import ScanMode, Status
from openclaw_audit.reports import json_out, sarif, markdown
from openclaw_audit.scanner import scan

from .conftest import FIXTURES, scan_fixture


def test_scan_produces_findings():
    v = scan_fixture("configs/gateway-noauth")
    assert v.findings, "scan produced no findings"
    assert any(f.status == Status.FAIL for f in v.findings)


def test_repo_only_mode_skips_instance_checks():
    """In repo-only mode, instance-only checks (e.g. file permissions) are skipped."""
    report = scan(target=FIXTURES / "docker/privileged", scan_mode=ScanMode.REPO_ONLY)
    perm = [f for f in report.findings if f.check_id == "OC-PERM-001"]
    if perm:
        assert all(f.status == Status.SKIP for f in perm)


def test_json_report_is_valid_json():
    report = scan(target=FIXTURES / "configs/gateway-noauth")
    text = json_out.render(report, None)
    data = json.loads(text)
    assert data["tool"] == "openclaw-audit"
    assert "findings" in data
    assert "scoring" in data


def test_sarif_report_renders():
    report = scan(target=FIXTURES / "configs/gateway-noauth")
    text = sarif.render(report, None)
    data = json.loads(text)
    assert data.get("version") == "2.1.0" or "runs" in data


def test_markdown_report_renders():
    report = scan(target=FIXTURES / "configs/gateway-noauth")
    text = markdown.render(report, None)
    assert "OpenClaw" in text or "Audit" in text
    assert len(text) > 100
