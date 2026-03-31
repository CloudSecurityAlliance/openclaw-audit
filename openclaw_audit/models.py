"""Data models for the OpenClaw Security Audit Tool."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


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
        return {
            "tool": "openclaw-audit",
            "version": "1.0.0",
            "target": self.target,
            "context_type": self.context_type,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }
