"""Strongly typed domain models for the scanner lifecycle."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sentinelllm.core.enums import (
    AdaptiveDecisionType,
    AttackCategory,
    CoverageStatus,
    HypothesisStatus,
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
    """Authentication metadata referencing secret material through the environment."""

    required: bool = False
    scheme: str | None = None
    header_name: str = "Authorization"
    environment_variable: str | None = None


@dataclass(frozen=True, slots=True)
class LLMConfiguration:
    """Provider-neutral model configuration; API secrets stay outside persisted state."""

    provider: str = "deterministic"
    model: str = ""
    endpoint: str | None = None
    api_key_environment_variable: str | None = None
    timeout_seconds: float = 20.0
    maximum_retries: int = 1

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ConfigurationError("LLM timeout_seconds must be greater than zero")
        if self.maximum_retries < 0:
            raise ConfigurationError("LLM maximum_retries must be zero or greater")


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
    llm: LLMConfiguration = field(default_factory=LLMConfiguration)
    timeout_seconds: float = 10.0
    retry: RetryConfiguration = field(default_factory=RetryConfiguration)
    enabled_attack_categories: tuple[AttackCategory, ...] = ()
    maximum_attack_iterations: int = 5
    maximum_jobs: int = 50
    maximum_requests: int = 50
    maximum_requests_per_endpoint: int = 10
    maximum_scan_duration_seconds: float = 300.0
    allowed_methods: tuple[str, ...] = ("GET", "POST")
    concurrency: int = 1
    minimum_request_interval_seconds: float = 0.0
    discovery_paths: tuple[str, ...] = ("/openapi.json", "/swagger.json")
    dry_run: bool = True
    reporting_output_directory: str = "./reports"

    def __post_init__(self) -> None:
        if not self.target_url.startswith(("http://", "https://")):
            raise ConfigurationError("target_url must use http or https")
        if self.timeout_seconds <= 0:
            raise ConfigurationError("timeout_seconds must be greater than zero")
        if self.maximum_attack_iterations < 1:
            raise ConfigurationError("maximum_attack_iterations must be at least one")
        if min(self.maximum_jobs, self.maximum_requests, self.maximum_requests_per_endpoint) < 1:
            raise ConfigurationError("scan request and job budgets must be at least one")
        if self.maximum_scan_duration_seconds <= 0:
            raise ConfigurationError("maximum_scan_duration_seconds must be greater than zero")
        if self.concurrency < 1:
            raise ConfigurationError("concurrency must be at least one")
        if self.minimum_request_interval_seconds < 0:
            raise ConfigurationError("minimum_request_interval_seconds cannot be negative")
        if not self.allowed_methods:
            raise ConfigurationError("at least one HTTP method must be allowed")

    def to_dict(self) -> dict[str, Any]:
        """Serialize configuration into plain data for persistence or logging."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EndpointProfile:
    """One discovered in-scope request surface."""

    url: str
    method: str
    parameters: tuple[str, ...] = ()
    content_types: tuple[str, ...] = ()
    source: str = "baseline"
    authentication_required: bool | None = None


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
    endpoint_profiles: tuple[EndpointProfile, ...] = ()
    interfaces: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    attack_surface: tuple[str, ...] = ()
    technology: tuple[str, ...] = ()
    discovery_evidence: tuple[str, ...] = ()
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
    strategy_id: str = ""
    description: str = ""
    success_criteria: tuple[str, ...] = ()
    stop_conditions: tuple[str, ...] = ()
    remediation_guidance: str = ""
    endpoint: str = ""
    method: str = "POST"
    parameter: str = "prompt"


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
    result_id: str = field(default_factory=lambda: str(uuid4()))
    request_fingerprint: str = ""


@dataclass(frozen=True, slots=True)
class Evidence:
    """A concrete observed fact referenced by judgments and findings."""

    evidence_id: str
    job_id: str
    kind: str
    summary: str
    value: Any = None
    baseline_value: Any = None


@dataclass(frozen=True, slots=True)
class Observation:
    """Structured response analysis with no vulnerability conclusion."""

    observation_id: str
    job_id: str
    summary: str
    signals: tuple[str, ...] = ()
    evidence_references: tuple[str, ...] = ()
    response_status: int | None = None
    content_type: str | None = None
    reflected_input: bool = False
    baseline_deviation: float = 0.0
    strategy_id: str = ""


@dataclass(frozen=True, slots=True)
class AttackHypothesis:
    """Explicit proposition that an adaptive attack attempts to establish."""

    hypothesis_id: str
    category: AttackCategory
    description: str
    objective: str
    expected_signal: str
    status: HypothesisStatus = HypothesisStatus.UNTESTED
    confidence: float = 0.0
    evidence_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class AdaptationDecision:
    """Concise, auditable metadata for one response-driven transition."""

    decision_id: str
    iteration: int
    decision: AdaptiveDecisionType
    previous_strategy_id: str
    next_strategy_id: str | None
    hypothesis_id: str
    evidence_references: tuple[str, ...]
    confidence: float
    reason: str
    triggering_job_id: str
    next_job_id: str | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Deterministic approval or rejection of a proposed attack job."""

    job_id: str
    approved: bool
    reason: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class CategoryCoverage:
    """Final coverage state for one OWASP 2026 category."""

    category: AttackCategory
    status: CoverageStatus
    strategies_available: int
    strategies_evaluated: int = 0
    finding_ids: tuple[str, ...] = ()
    confidence: float = 0.0


@dataclass(frozen=True, slots=True)
class JudgeResult:
    """Judgment about whether an attack result met its stated objective."""

    outcome: JudgeOutcome
    confidence: float
    reason: str
    evidence_references: tuple[str, ...] = ()
    job_id: str = ""
    matched_criteria: tuple[str, ...] = ()
    recommended_action: AdaptiveDecisionType = AdaptiveDecisionType.STOP

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
    missing_security_control: str = ""
    immediate_actions: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()
    validation_steps: tuple[str, ...] = ()
    verification_status: VerificationStatus = VerificationStatus.PENDING
    affected_target: str = ""
    affected_endpoint: str = ""
    affected_component: str = ""
    reproduction_summary: str = ""
    job_ids: tuple[str, ...] = ()
    result_ids: tuple[str, ...] = ()
    strategy_ids: tuple[str, ...] = ()
    verification_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class ScanHistory:
    """Aggregate record capable of representing a complete future scan lifecycle."""

    scan: ScanConfiguration
    status: ScanStatus = ScanStatus.PENDING
    target_profile: TargetProfile | None = None
    plans: tuple[AttackPlan, ...] = ()
    jobs: tuple[AttackJob, ...] = ()
    results: tuple[AttackResult, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    observations: tuple[Observation, ...] = ()
    judge_results: tuple[JudgeResult, ...] = ()
    hypotheses: tuple[AttackHypothesis, ...] = ()
    adaptations: tuple[AdaptationDecision, ...] = ()
    policy_decisions: tuple[PolicyDecision, ...] = ()
    coverage: tuple[CategoryCoverage, ...] = ()
    candidate_findings: tuple[Finding, ...] = ()
    findings: tuple[Finding, ...] = ()
    verification_results: tuple[dict[str, Any], ...] = ()
    errors: tuple[str, ...] = ()
    duplicate_jobs_prevented: int = 0
    rejected_jobs: int = 0
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
