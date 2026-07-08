"""Data models for the vulnerability agent pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FixStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


@dataclass
class Vulnerability:
    """A detected gem vulnerability."""

    gem: str
    current_version: str
    patched_versions: list[str]
    cve: str
    title: str = ""
    severity: Severity = Severity.MEDIUM
    advisory_url: str = ""
    description: str = ""


@dataclass
class AnalysisResult:
    """Result of AI analysis for a vulnerability."""

    vulnerability: Vulnerability
    recommended_version: str
    breaking_changes: list[str] = field(default_factory=list)
    migration_steps: list[str] = field(default_factory=list)
    rails_compatibility: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    risk_score: float = 0.0
    changelog_summary: str = ""
    requires_code_changes: bool = False
    code_change_description: str = ""
    safe_to_auto_upgrade: bool = True


@dataclass
class FixResult:
    """Result of attempting to fix a vulnerability."""

    vulnerability: Vulnerability
    status: FixStatus = FixStatus.PENDING
    gemfile_changes: list[str] = field(default_factory=list)
    code_changes: list[str] = field(default_factory=list)
    verification_output: str = ""
    error_message: str = ""
    attempts: int = 0
    pr_url: Optional[str] = None


@dataclass
class VerificationResult:
    """Result of running verification suite."""

    success: bool
    bundle_install: bool = False
    tests_passed: bool = False
    rubocop_passed: bool = False
    brakeman_passed: bool = False
    audit_clean: bool = False
    zeitwerk_check: bool = False
    stdout: str = ""
    stderr: str = ""
    failed_specs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class AgentState:
    """Full state of the agent pipeline."""

    rails_app_path: str = ""
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    analyses: list[AnalysisResult] = field(default_factory=list)
    fix_results: list[FixResult] = field(default_factory=list)
    current_vulnerability_index: int = 0
    retry_count: int = 0
    max_retries: int = 3
    dry_run: bool = False
    target_gem: Optional[str] = None
    pr_url: Optional[str] = None
