"""Data models for the OpenClaw Security Audit Tool."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Exposure Scoring (per openclaw_scoring_spec.md v1)
# ---------------------------------------------------------------------------

TIER1_CHECK_IDS = frozenset({
    "OC-SKILL-001", "OC-SKILL-002", "OC-SKILL-003", "OC-SKILL-004",
    "OC-CRED-002", "OC-CRED-004",
    "OC-MCP-001",
    "OC-DOCK-004", "OC-DOCK-006", "OC-NET-001",
    "OC-PERM-002",
    "OC-SOUL-001", "OC-SOUL-007",
})

_NO_CONFIG_NEEDLE = "No config file found"


class Severity(enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(enum.Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


class Applicability(enum.Enum):
    REPO_ONLY = "repo_only"
    INSTANCE_ONLY = "instance_only"
    BOTH = "both"


class FixLevel(enum.Enum):
    BASIC = "basic"
    MEDIUM = "medium"
    COMPLETE = "complete"


class ScanMode(enum.Enum):
    AUTO = "auto"
    REPO_ONLY = "repo_only"
    INSTANCE_ONLY = "instance_only"


class ContextType(enum.Enum):
    INSTALLED_INSTANCE = "installed_instance"
    GIT_REPO = "git_repo"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


@dataclass
class FrameworkMapping:
    owasp_asi: list[str] = field(default_factory=list)
    atlas: list[str] = field(default_factory=list)
    aicm: list[str] = field(default_factory=list)
    maestro: list[str] = field(default_factory=list)
    whitepaper_section: str = ""

    def to_dict(self) -> dict:
        d: dict[str, Any] = {}
        if self.owasp_asi:
            d["OWASP_ASI"] = self.owasp_asi
        if self.atlas:
            d["MITRE_ATLAS"] = self.atlas
        if self.aicm:
            d["AICM"] = self.aicm
        if self.maestro:
            d["MAESTRO"] = self.maestro
        if self.whitepaper_section:
            d["whitepaper_section"] = self.whitepaper_section
        return d


@dataclass
class CheckDefinition:
    check_id: str
    title: str
    description: str
    category: str
    severity: Severity
    applicability: Applicability
    frameworks: FrameworkMapping
    recommendation: str
    fix_level: Optional[FixLevel] = None  # None = not auto-fixable


@dataclass
class Finding:
    check_id: str
    status: Status
    title: str
    severity: Severity
    category: str
    description: str
    detail: str = ""
    evidence: str = ""
    file_path: str = ""
    recommendation: str = ""
    frameworks: Optional[FrameworkMapping] = None
    fix_level: Optional[FixLevel] = None
    fix_applied: bool = False
    fix_description: str = ""

    def to_dict(self) -> dict:
        d = {
            "id": self.check_id,
            "status": self.status.value,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
        }
        if self.detail:
            d["detail"] = self.detail
        if self.evidence:
            d["evidence"] = self.evidence
        if self.file_path:
            d["file_path"] = self.file_path
        if self.recommendation:
            d["recommendation"] = self.recommendation
        if self.frameworks:
            d["frameworks"] = self.frameworks.to_dict()
        if self.fix_applied:
            d["fix_applied"] = True
            d["fix_description"] = self.fix_description
        return d


@dataclass
class ScanContext:
    target_path: Path
    context_type: ContextType = ContextType.UNKNOWN
    scan_mode: ScanMode = ScanMode.AUTO
    config_files: list[Path] = field(default_factory=list)
    soul_files: list[Path] = field(default_factory=list)
    heartbeat_files: list[Path] = field(default_factory=list)
    skill_dirs: list[Path] = field(default_factory=list)
    skill_files: list[Path] = field(default_factory=list)
    mcp_config_files: list[Path] = field(default_factory=list)
    docker_files: list[Path] = field(default_factory=list)
    env_files: list[Path] = field(default_factory=list)
    agent_dirs: list[Path] = field(default_factory=list)
    memory_dirs: list[Path] = field(default_factory=list)
    session_dirs: list[Path] = field(default_factory=list)
    openclaw_version: Optional[str] = None
    is_nemoclaw: bool = False
    nemoclaw_policy_files: list[Path] = field(default_factory=list)


@dataclass
class ScanReport:
    target: str
    context_type: str
    scan_mode: str = "auto"
    findings: list[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def compute_summary(self) -> None:
        total = len(self.findings)
        by_status = {}
        by_severity = {}
        by_category = {}
        for f in self.findings:
            by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            cat = by_category.setdefault(f.category, {"PASS": 0, "WARN": 0, "FAIL": 0})
            if f.status.value in cat:
                cat[f.status.value] += 1
        # Preserve any extra keys (like fix_actions) already in summary
        extra = {k: v for k, v in self.summary.items()
                 if k not in ("total_checks", "by_status", "by_severity", "by_category")}
        self.summary = {
            "total_checks": total,
            "by_status": by_status,
            "by_severity": by_severity,
            "by_category": by_category,
            **extra,
        }

    def to_dict(self) -> dict:
        self.compute_summary()
        d = {
            "tool": "openclaw-audit",
            "version": "1.0.0",
            "target": self.target,
            "context_type": self.context_type,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.scan_mode != "auto":
            d["scan_mode"] = self.scan_mode
        # Include scoring in serialised output
        score = compute_score(self.findings)
        d["scoring"] = score.to_dict()
        return d


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

@dataclass
class ScoreResult:
    tier1_count: int = 0
    tier2_count: int = 0
    tier3_count: int = 0
    exposure_score: int = 0
    grade: str = ""       # "RED", "YELLOW", or "GREEN"
    grade_icon: str = ""  # emoji
    confidence: str = ""       # "High", "Medium", or "Low"
    confidence_icon: str = ""  # emoji
    has_critical: bool = False
    key_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tier1_count": self.tier1_count,
            "tier2_count": self.tier2_count,
            "tier3_count": self.tier3_count,
            "exposure_score": self.exposure_score,
            "grade": self.grade,
            "confidence": self.confidence,
            "has_critical": self.has_critical,
            "key_signals": self.key_signals,
        }


def compute_score(findings: list[Finding]) -> ScoreResult:
    """Compute exposure score, grade, and confidence from a list of findings."""
    tier1 = 0
    tier2 = 0
    tier3 = 0
    has_critical = False
    key_signals: list[str] = []

    # Track artifact presence for confidence
    has_tier1 = False
    artifact_categories = set()

    for f in findings:
        if f.status == Status.SKIP:
            continue

        # Track artifact presence
        if f.status in (Status.PASS, Status.FAIL, Status.WARN):
            artifact_categories.add(f.category)

        if f.severity == Severity.CRITICAL and f.status == Status.FAIL:
            has_critical = True

        if f.status == Status.FAIL:
            if f.check_id in TIER1_CHECK_IDS:
                tier1 += 1
                has_tier1 = True
                key_signals.append(f"{f.check_id}: {f.title}")
            else:
                tier2 += 1
        elif f.status == Status.WARN:
            if _NO_CONFIG_NEEDLE in (f.detail or ""):
                tier3 += 1
            else:
                tier2 += 1
                key_signals.append(f"{f.check_id}: {f.title}")

    exposure_score = (tier1 * 3) + (tier2 * 1)

    # Grade
    if exposure_score >= 6 or has_critical:
        grade, grade_icon = "RED", "\U0001f7e5"
    elif exposure_score >= 2:
        grade, grade_icon = "YELLOW", "\U0001f7e8"
    else:
        grade, grade_icon = "GREEN", "\U0001f7e9"

    # Confidence
    # High: Tier1 findings exist OR meaningful artifacts found
    meaningful_artifacts = {"Docker Sandbox", "Skill Vetting", "MCP Server Audit",
                           "Credential Hygiene"}
    has_meaningful = bool(artifact_categories & meaningful_artifacts)
    if has_tier1 or has_meaningful:
        confidence, confidence_icon = "High", "\u2714"
    elif tier2 > 0 and len(artifact_categories) > 1:
        confidence, confidence_icon = "Medium", "\u2796"
    else:
        confidence, confidence_icon = "Low", "\u2753"

    # Cap key signals to top 5
    key_signals = key_signals[:5]

    return ScoreResult(
        tier1_count=tier1,
        tier2_count=tier2,
        tier3_count=tier3,
        exposure_score=exposure_score,
        grade=grade,
        grade_icon=grade_icon,
        confidence=confidence,
        confidence_icon=confidence_icon,
        has_critical=has_critical,
        key_signals=key_signals,
    )
