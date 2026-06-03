"""Policy-as-code for openclaw-audit.

A policy lets an organization declare what "acceptable OpenClaw posture" means:
which findings count as gate failures, which risks are explicitly accepted
(with justification), and what severity thresholds fail a CI build.

The policy file is JSON by default (zero dependencies). YAML (.yaml/.yml) is
also accepted when PyYAML is installed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .models import Finding, ScanReport, Severity, Status

POLICY_FILENAMES = (
    "openclaw-audit.policy.json",
    "openclaw-audit.policy.yaml",
    "openclaw-audit.policy.yml",
)

_SEVERITY_BY_NAME = {s.value.lower(): s for s in Severity}


class PolicyError(ValueError):
    """Raised for malformed or invalid policy files."""


@dataclass
class AcceptedRisk:
    check: str
    justification: str


@dataclass
class Policy:
    profile: str = ""
    fail_on: frozenset = field(default_factory=frozenset)  # set[Severity]
    max_critical: Optional[int] = None
    max_high: Optional[int] = None
    accepted_risks: dict = field(default_factory=dict)  # check_id -> justification
    required_controls: list = field(default_factory=list)
    source: str = ""

    @property
    def has_gate(self) -> bool:
        return bool(self.fail_on) or self.max_critical is not None \
            or self.max_high is not None or bool(self.required_controls)


@dataclass
class PolicyResult:
    gate_passed: bool
    violations: list = field(default_factory=list)
    accepted_count: int = 0

    def to_dict(self) -> dict:
        return {
            "gate_passed": self.gate_passed,
            "violations": self.violations,
            "accepted_count": self.accepted_count,
        }


def _parse_text(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as e:
            raise PolicyError(
                f"{path.name} is YAML but PyYAML is not installed. Install it "
                "(`pip install pyyaml`) or use a .json policy file."
            ) from e
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise PolicyError(f"{path.name}: top level must be a mapping/object.")
    return data


def _parse_severities(values, where: str) -> frozenset:
    out = set()
    for v in values or []:
        sev = _SEVERITY_BY_NAME.get(str(v).lower())
        if sev is None:
            raise PolicyError(f"{where}: unknown severity {v!r}.")
        out.add(sev)
    return frozenset(out)


def load_policy(path: Path) -> Policy:
    """Load and validate a policy file."""
    if not path.exists():
        raise PolicyError(f"Policy file not found: {path}")
    try:
        data = _parse_text(path)
    except (json.JSONDecodeError, OSError) as e:
        raise PolicyError(f"Could not parse policy {path}: {e}") from e

    ci_gate = data.get("ci_gate", {}) or {}
    risk = data.get("risk_acceptance", {}) or {}

    fail_on = _parse_severities(ci_gate.get("fail_on"), "ci_gate.fail_on")

    def _int_or_none(d, key):
        val = d.get(key)
        if val is None:
            return None
        if not isinstance(val, int):
            raise PolicyError(f"{key} must be an integer, got {val!r}.")
        return val

    max_critical = _int_or_none(risk, "max_critical")
    max_high = _int_or_none(risk, "max_high")

    accepted: dict = {}
    for entry in data.get("accepted_risks", []) or []:
        if not isinstance(entry, dict) or "check" not in entry:
            raise PolicyError("each accepted_risks entry needs a 'check' field.")
        justification = entry.get("justification", "").strip()
        if not justification:
            raise PolicyError(
                f"accepted risk for {entry['check']} requires a non-empty "
                "'justification'."
            )
        accepted[entry["check"]] = justification

    required = list(data.get("required_controls", []) or [])

    return Policy(
        profile=str(data.get("profile", "")),
        fail_on=fail_on,
        max_critical=max_critical,
        max_high=max_high,
        accepted_risks=accepted,
        required_controls=required,
        source=str(path),
    )


def find_policy(root: Path) -> Optional[Path]:
    """Return the first policy file found in *root*, or None."""
    for name in POLICY_FILENAMES:
        candidate = root / name
        if candidate.exists():
            return candidate
    return None


def evaluate(report: ScanReport, policy: Policy) -> PolicyResult:
    """Evaluate findings against a policy, tagging findings in place.

    Marks each finding's ``policy_status`` as "accepted" or "violation" and
    returns a PolicyResult with the gate decision.
    """
    violations: list[str] = []
    accepted_count = 0
    crit = high = 0

    gate_set = policy.fail_on or frozenset()

    for f in report.findings:
        if f.status != Status.FAIL:
            continue
        if f.check_id in policy.accepted_risks:
            f.policy_status = "accepted"
            accepted_count += 1
            continue
        # A gate is in force for this finding if fail_on lists its severity,
        # or fail_on is empty but severity thresholds apply.
        gated = (f.severity in gate_set) if gate_set else True
        if gated:
            f.policy_status = "violation"
            violations.append(f"{f.check_id} ({f.severity.value}): {f.title}")
        if f.severity == Severity.CRITICAL:
            crit += 1
        elif f.severity == Severity.HIGH:
            high += 1

    # Required controls must be present and passing.
    by_id_status: dict[str, set] = {}
    for f in report.findings:
        by_id_status.setdefault(f.check_id, set()).add(f.status)
    for ctrl in policy.required_controls:
        statuses = by_id_status.get(ctrl)
        if statuses is None:
            violations.append(f"required control {ctrl} not evaluated")
        elif Status.FAIL in statuses or statuses == {Status.SKIP}:
            violations.append(f"required control {ctrl} not satisfied")

    gate_passed = True
    if gate_set and any(
        f.policy_status == "violation" for f in report.findings
    ):
        gate_passed = False
    if policy.max_critical is not None and crit > policy.max_critical:
        gate_passed = False
    if policy.max_high is not None and high > policy.max_high:
        gate_passed = False
    if any(v.startswith("required control") for v in violations):
        gate_passed = False
    # With no explicit severity gate but a violation list, fail if any violation.
    if not gate_set and policy.max_critical is None and policy.max_high is None \
            and not policy.required_controls and violations:
        gate_passed = False

    return PolicyResult(
        gate_passed=gate_passed,
        violations=violations,
        accepted_count=accepted_count,
    )
