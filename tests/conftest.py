"""Shared test fixtures and helpers for the openclaw-audit test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from openclaw_audit.models import ScanMode, Status
from openclaw_audit.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"


class FindingsView:
    """Convenience wrapper over a scan's findings, indexed by check_id."""

    def __init__(self, findings):
        self.findings = findings
        self._by_id: dict[str, list] = {}
        for f in findings:
            self._by_id.setdefault(f.check_id, []).append(f)

    def for_check(self, check_id: str) -> list:
        return self._by_id.get(check_id, [])

    def status(self, check_id: str):
        """Return the 'worst' status seen for a check_id (FAIL > WARN > PASS > SKIP)."""
        order = {Status.FAIL: 4, Status.WARN: 3, Status.PASS: 2, Status.SKIP: 1}
        results = self.for_check(check_id)
        if not results:
            return None
        return max((f.status for f in results), key=lambda s: order.get(s, 0))

    def failed(self, check_id: str) -> bool:
        return self.status(check_id) == Status.FAIL

    def passed(self, check_id: str) -> bool:
        return self.status(check_id) == Status.PASS

    def has_status(self, check_id: str, status: Status) -> bool:
        return any(f.status == status for f in self.for_check(check_id))

    @property
    def fail_ids(self) -> set[str]:
        return {f.check_id for f in self.findings if f.status == Status.FAIL}


def scan_fixture(name: str, scan_mode: ScanMode = ScanMode.AUTO) -> FindingsView:
    """Scan a fixture directory under tests/fixtures/ and return a FindingsView."""
    target = FIXTURES / name
    assert target.exists(), f"fixture not found: {target}"
    report = scan(target=target, scan_mode=scan_mode)
    return FindingsView(report.findings)


@pytest.fixture
def scan_fixture_fn():
    return scan_fixture
