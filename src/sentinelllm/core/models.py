"""Strongly typed domain models for the scanner lifecycle."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sentinelllm.core.enums import (
    AttackCategory,
    JobStatus,
    JudgeOutcome,
    RiskLevel,
    ScanStatus,
    VerificationStatus,
)
from sentinelllm.core.errors import ConfigurationError


def utc_now() -> datetime:
    """Return a timezone-aware timestamp for lifecycle records."""
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AuthenticationConfiguration:
    """Authentication metadata; secret material is deliberately excluded."""

    required: bool = False
    scheme: str | None = None


@dataclass(frozen=True, slots=True)
class RetryConfiguration:
    """Retry limits for target operations."""

    attempts: int = 2

    def __post_init__(self) -> None:
        if self.attempts < 0:
            raise ConfigurationError("retry attempts must be zero or greater")


@dataclass(frozen=True, slots=True)
class ScanConfiguration:
    """Runtime configuration for one scan."""

    target_url: str
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    authentication: AuthenticationConfiguration = field(default_factory=AuthenticationConfiguration)
    timeout_seconds: float = 10.0
    retry: RetryConfiguration = field(default_factory=RetryConfiguration)
    enabled_attack_categories: tuple[AttackCategory, ...] = ()
    maximum_attack_iterations: int = 5
    dry_run: bool = True
    reporting_output_directory: str = "./reports"

    def __post_init__(self) -> None:
        if not self.target_url.startswith(("http://", "https://")):
            raise ConfigurationError("target_url must use http or https")
        if self.timeout_seconds <= 0:
            raise ConfigurationError("timeout_seconds must be greater than zero")
        if self.maximum_attack_iterations < 1:
            raise ConfigurationError("maximum_attack_iterations must be at least one")

    def to_dict(self) -> dict[str, Any]:
        """Serialize configuration into plain data for persistence or logging."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TargetProfile:
    """Information discovered about the target application and its attack surface."""

    target_url: str
    application_name: str | None = None
    has_llm: bool | None = None
    has_rag: bool | None = None
    has_memory: bool | None = None
    has_tools: bool | None = None
    is_multi_tenant: bool | None = None
    is_multi_role: bool | None = None
    has_structured_output: bool | None = None
    retrieved_documents: bool | None = None
    tool_calls: bool | None = None
    authentication_required: bool | None = None
    identified_endpoints: tuple[str, ...] = ()
    attack_surface: tuple[str, ...] = ()
    discovery_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AttackPlan:
    """A structured, unexecuted security test plan."""

    attack_id: str
    category: AttackCategory
    owasp_mapping: str
    objective: str
    preconditions: tuple[str, ...]
    strategy: str
    expected_indicators: tuple[str, ...]
    risk_level: RiskLevel


@dataclass(frozen=True, slots=True)
class AttackJob:
    """One scheduled iteration of an attack plan."""

    job_id: str
    scan_id: str
    attack_id: str
    iteration: int
    timestamp: datetime = field(default_factory=utc_now)
    status: JobStatus = JobStatus.PENDING
    request: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AttackResult:
    """Raw result of one attack job execution, without a security conclusion."""

    job_id: str
    http_status: int | None
    response: str | None
    response_metadata: dict[str, Any] = field(default_factory=dict)
    execution_duration_seconds: float | None = None
    evidence: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class JudgeResult:
    """Judgment about whether an attack result met its stated objective."""

    outcome: JudgeOutcome
    confidence: float
    reason: str
    evidence_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class Finding:
    """A security finding produced only by a future evaluator implementation."""

    finding_id: str
    title: str
    description: str
    severity: RiskLevel
    confidence: float
    owasp_category: str
    attack_id: str
    evidence: tuple[str, ...]
    impact: str
    remediation: str
    verification_status: VerificationStatus = VerificationStatus.PENDING

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class ScanHistory:
    """Aggregate record capable of representing a complete future scan lifecycle."""

    scan: ScanConfiguration
    status: ScanStatus = ScanStatus.PENDING
    jobs: tuple[AttackJob, ...] = ()
    results: tuple[AttackResult, ...] = ()
    judge_results: tuple[JudgeResult, ...] = ()
    findings: tuple[Finding, ...] = ()
    verification_results: tuple[str, ...] = ()
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
