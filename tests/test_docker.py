"""Tests for Docker hardening checks (OC-DOCK-*)."""

from .conftest import scan_fixture


def test_privileged_compose_flagged():
    v = scan_fixture("docker/privileged")
    # Privileged mode, docker.sock mount, host network, root user, latest tag
    assert v.failed("OC-DOCK-006"), "privileged: true not flagged"
    assert v.failed("OC-DOCK-004"), "dangerous bind mount (docker.sock) not flagged"
    assert v.failed("OC-NET-001"), "host networking not flagged"


def test_hardened_compose_clean():
    v = scan_fixture("docker/hardened")
    dock_fails = {cid for cid in v.fail_ids if cid.startswith("OC-DOCK")}
    assert not dock_fails, f"hardened compose produced DOCK fails: {dock_fails}"
