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


class Confidence(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvidenceQuality(enum.Enum):
    PATTERN_MATCH = "pattern_match"
    CONFIG_VALUE = "config_value"
    CORRELATED_PATH = "correlated_path"
    RUNTIME_VERIFIED = "runtime_verified"
    POLICY_VIOLATION = "policy_violation"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


class Exploitability(enum.Enum):
    THEORETICAL = "theoretical"
    PLAUSIBLE = "plausible"
    DEMONSTRATED = "demonstrated"


class BlastRadius(enum.Enum):
    LOCAL_USER = "local_user"
    WORKSPACE = "workspace"
    HOST = "host"
    CLOUD_ACCOUNT = "cloud_account"
    ENTERPRISE = "enterprise"
    UNKNOWN = "unknown"


class FixLevel(enum.Enum):
    BASIC = "basic"
    MEDIUM = "medium"
    COMPLETE = "complete"


class ScanMode(enum.Enum):
    AUTO = "auto"
    REPO_ONLY = "repo_only"
    INSTANCE_ONLY = "instance_only"


class Profile(enum.Enum):
    """Explicit scan profiles layered over ScanMode.

    A profile fixes the scan mode and (for CI) the severity gate, so users and
    CI systems get predictable behavior instead of relying on auto-detection.
    """
    UPSTREAM_REPO = "upstream-repo"
    IMPLEMENTATION_REPO = "implementation-repo"
    LOCAL_INSTANCE = "local-instance"
    ENTERPRISE_FLEET = "enterprise-fleet"
    CI_PR_GATE = "ci-pr-gate"

    @property
    def scan_mode(self) -> "ScanMode":
        if self in (Profile.LOCAL_INSTANCE, Profile.ENTERPRISE_FLEET):
            return ScanMode.INSTANCE_ONLY
        return ScanMode.REPO_ONLY

    @property
    def gate_severities(self) -> frozenset:
        """Severities that fail the build under this profile (empty = no gate)."""
        if self == Profile.CI_PR_GATE:
            return frozenset({Severity.CRITICAL, Severity.HIGH})
        return frozenset()


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
    # Triage metadata. When left None, sensible defaults are derived per
    # check namespace at enrichment time (see derive_finding_metadata).
    confidence: Optional["Confidence"] = None
    evidence_quality: Optional["EvidenceQuality"] = None
    exploitability: Optional["Exploitability"] = None
    blast_radius: Optional["BlastRadius"] = None


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
    # Triage metadata (see derive_finding_metadata / scanner enrichment).
    confidence: Optional[Confidence] = None
    evidence_quality: Optional[EvidenceQuality] = None
    exploitability: Optional[Exploitability] = None
    blast_radius: Optional[BlastRadius] = None
    # Set of attack-path finding IDs this finding contributes evidence to.
    attack_path: str = ""
    # Where this check applies (repo_only / instance_only / both).
    profile_applicability: str = ""
    # Policy evaluation status: "" (no policy), "violation", or "accepted".
    policy_status: str = ""

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
        if self.confidence:
            d["confidence"] = self.confidence.value
        if self.evidence_quality:
            d["evidence_quality"] = self.evidence_quality.value
        if self.exploitability:
            d["exploitability"] = self.exploitability.value
        if self.blast_radius:
            d["blast_radius"] = self.blast_radius.value
        if self.attack_path:
            d["attack_path"] = self.attack_path
        if self.profile_applicability:
            d["profile_applicability"] = self.profile_applicability
        if self.policy_status:
            d["policy_status"] = self.policy_status
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
    # CapabilityProfile objects, populated by the scanner before checks run.
    capability_profiles: list = field(default_factory=list)


@dataclass
class ScanReport:
    target: str
    context_type: str
    scan_mode: str = "auto"
    findings: list[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    # Capability profiles (list of dicts from CapabilityProfile.to_dict()).
    capability_profiles: list[dict] = field(default_factory=list)

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
        if self.capability_profiles:
            d["capability_profiles"] = self.capability_profiles
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

    # Track artifact presence for confidence — only count categories
    # where there is a real (non-tier3) FAIL or WARN, not just PASS.
    has_tier1 = False
    observed_artifact_categories = set()

    for f in findings:
        if f.status == Status.SKIP:
            continue

        if f.severity == Severity.CRITICAL and f.status == Status.FAIL:
            has_critical = True

        if f.status == Status.FAIL:
            if f.check_id in TIER1_CHECK_IDS:
                tier1 += 1
                has_tier1 = True
                key_signals.append(f"{f.check_id}: {f.title}")
            else:
                tier2 += 1
                key_signals.append(f"{f.check_id}: {f.title}")
            observed_artifact_categories.add(f.category)
        elif f.status == Status.WARN:
            if _NO_CONFIG_NEEDLE in (f.detail or ""):
                tier3 += 1
                # Tier 3 config-inference warnings do NOT count as
                # observed artifacts and are excluded from signals.
            else:
                tier2 += 1
                key_signals.append(f"{f.check_id}: {f.title}")
                observed_artifact_categories.add(f.category)

    exposure_score = (tier1 * 3) + (tier2 * 1)

    # Grade
    if exposure_score >= 6 or has_critical:
        grade, grade_icon = "RED", "\U0001f7e5"
    elif exposure_score >= 2:
        grade, grade_icon = "YELLOW", "\U0001f7e8"
    else:
        grade, grade_icon = "GREEN", "\U0001f7e9"

    # Confidence — based on strength of observed evidence, not just
    # category presence.  Tier 3 config-inference findings and bare
    # PASS results are intentionally excluded.
    if has_tier1:
        confidence, confidence_icon = "High", "\u2714"
    elif len(observed_artifact_categories) >= 1:
        # Real FAIL/WARN findings in at least one meaningful category
        confidence, confidence_icon = "Medium", "\u2796"
    else:
        confidence, confidence_icon = "Low", "\u2753"

    # Cap key signals — prioritise tier1 (already first), then tier2
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


# ---------------------------------------------------------------------------
# Triage-metadata derivation
# ---------------------------------------------------------------------------

# Check namespaces whose findings rest on regex / textual pattern matches.
# These are inherently lower-confidence than parsed config values.
_PATTERN_PREFIXES = ("OC-SKILL", "OC-SOUL", "OC-CRED")
_PATTERN_IDS = frozenset({"OC-MCP-004"})  # tool-description injection

# Default blast radius by namespace, with per-id overrides for the cases
# where exposure clearly reaches further than the namespace default.
_BLAST_BY_PREFIX = {
    "OC-CFG": BlastRadius.HOST,
    "OC-NET": BlastRadius.HOST,
    "OC-DOCK": BlastRadius.HOST,
    "OC-VER": BlastRadius.HOST,
    "OC-PERM": BlastRadius.HOST,
    "OC-SKILL": BlastRadius.WORKSPACE,
    "OC-SOUL": BlastRadius.WORKSPACE,
    "OC-MCP": BlastRadius.WORKSPACE,
    "OC-AGENT": BlastRadius.WORKSPACE,
    "OC-CRED": BlastRadius.CLOUD_ACCOUNT,
    "OC-PATH": BlastRadius.HOST,
}
_BLAST_BY_ID = {
    "OC-CFG-011": BlastRadius.CLOUD_ACCOUNT,  # browser SSRF → metadata creds
    "OC-SKILL-006": BlastRadius.CLOUD_ACCOUNT,  # credential theft
    "OC-PATH-003": BlastRadius.CLOUD_ACCOUNT,  # secret-to-egress
    "OC-PATH-004": BlastRadius.CLOUD_ACCOUNT,  # public agent + private net
}


def _prefix(check_id: str) -> str:
    parts = check_id.split("-")
    return "-".join(parts[:2]) if len(parts) >= 2 else check_id


def derive_finding_metadata(
    check_id: str, severity: Severity, status: Status,
) -> tuple[Confidence, EvidenceQuality, Exploitability, BlastRadius]:
    """Derive default triage metadata for a finding from its check id.

    Used to fill any metadata fields a check (or check definition) did not set
    explicitly. Correlated attack-path findings (OC-PATH-*) are treated as
    higher-confidence, higher-evidence than single-signal findings.
    """
    prefix = _prefix(check_id)

    # Evidence quality
    if prefix == "OC-PATH":
        evidence_quality = EvidenceQuality.CORRELATED_PATH
    elif prefix == "OC-RUNTIME":
        evidence_quality = EvidenceQuality.RUNTIME_VERIFIED
    elif check_id in _PATTERN_IDS or prefix in _PATTERN_PREFIXES:
        evidence_quality = EvidenceQuality.PATTERN_MATCH
    else:
        evidence_quality = EvidenceQuality.CONFIG_VALUE

    # Confidence: config/correlated/runtime evidence is strong; pattern is
    # medium; a passing or skipped check is not an assertion of risk.
    if status in (Status.PASS, Status.SKIP):
        confidence = Confidence.HIGH
    elif evidence_quality == EvidenceQuality.PATTERN_MATCH:
        confidence = Confidence.MEDIUM
    elif evidence_quality in (
        EvidenceQuality.CORRELATED_PATH,
        EvidenceQuality.RUNTIME_VERIFIED,
        EvidenceQuality.CONFIG_VALUE,
    ):
        confidence = Confidence.HIGH
    else:
        confidence = Confidence.MEDIUM

    # Exploitability: correlated/runtime paths are the closest to demonstrated;
    # a confirmed FAIL is plausible; a WARN is theoretical.
    if status == Status.FAIL and evidence_quality in (
        EvidenceQuality.CORRELATED_PATH, EvidenceQuality.RUNTIME_VERIFIED,
    ):
        exploitability = Exploitability.DEMONSTRATED
    elif status == Status.FAIL:
        exploitability = Exploitability.PLAUSIBLE
    else:
        exploitability = Exploitability.THEORETICAL

    # Blast radius
    blast_radius = _BLAST_BY_ID.get(check_id) or _BLAST_BY_PREFIX.get(
        prefix, BlastRadius.UNKNOWN
    )

    return confidence, evidence_quality, exploitability, blast_radius


def enrich_finding(finding: Finding, check: Optional[CheckDefinition] = None) -> None:
    """Populate a finding's triage metadata in place.

    Precedence: explicit value already on the finding > value on the check
    definition > derived default. Mutates and returns nothing.
    """
    d_conf, d_eq, d_exp, d_blast = derive_finding_metadata(
        finding.check_id, finding.severity, finding.status,
    )
    if finding.confidence is None:
        finding.confidence = (check.confidence if check else None) or d_conf
    if finding.evidence_quality is None:
        finding.evidence_quality = (check.evidence_quality if check else None) or d_eq
    if finding.exploitability is None:
        finding.exploitability = (check.exploitability if check else None) or d_exp
    if finding.blast_radius is None:
        finding.blast_radius = (check.blast_radius if check else None) or d_blast
    if not finding.profile_applicability and check is not None:
        finding.profile_applicability = check.applicability.value
