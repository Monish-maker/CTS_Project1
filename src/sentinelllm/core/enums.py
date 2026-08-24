"""Enumerations shared across SentinelLLM contracts."""

from enum import StrEnum


class AttackCategory(StrEnum):
    """High-level attack categories enabled for a scan."""

    PROMPT_INJECTION = "prompt_injection"
    SENSITIVE_INFORMATION_DISCLOSURE = "sensitive_information_disclosure"
    EXCESSIVE_AGENCY = "excessive_agency"
    SUPPLY_CHAIN = "supply_chain"
    DATA_AND_MODEL_POISONING = "data_and_model_poisoning"
    UNBOUNDED_CONSUMPTION = "unbounded_consumption"
    MISINFORMATION = "misinformation"
    HIDDEN_CONTEXT_EXPOSURE = "hidden_context_exposure"
    VECTOR_AND_EMBEDDING_WEAKNESSES = "vector_and_embedding_weaknesses"
    IMPROPER_OUTPUT_HANDLING = "improper_output_handling"
    INSECURE_OUTPUT_HANDLING = "improper_output_handling"


class HypothesisStatus(StrEnum):
    """Lifecycle state of an explicit attack hypothesis."""

    UNTESTED = "untested"
    ACTIVE = "active"
    SUPPORTED = "supported"
    WEAKENED = "weakened"
    DISPROVED = "disproved"
    CONFIRMED = "confirmed"
    ABANDONED = "abandoned"


class AdaptiveDecisionType(StrEnum):
    """Auditable action selected after judging an attack result."""

    CONTINUE_STRATEGY = "continue_strategy"
    REFINE_STRATEGY = "refine_strategy"
    SWITCH_STRATEGY = "switch_strategy"
    CHANGE_PARAMETER = "change_parameter"
    CHANGE_ENDPOINT = "change_endpoint"
    PURSUE_HYPOTHESIS = "pursue_hypothesis"
    VERIFY = "verify"
    STOP = "stop"


class CoverageStatus(StrEnum):
    """Assessment status for an OWASP category."""

    VULNERABLE = "vulnerable"
    NO_FINDING = "no_finding"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"


class RiskLevel(StrEnum):
    """Potential impact level of a planned test or finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class JobStatus(StrEnum):
    """Lifecycle state of a planned attack execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


class JudgeOutcome(StrEnum):
    """Conclusion produced by an attack judge."""

    FAILED = "failed"
    PARTIAL = "partial"
    SUCCESSFUL = "successful"
    INCONCLUSIVE = "inconclusive"
    POTENTIAL_SUCCESS = "potential_success"
    ERROR = "error"


class VerificationStatus(StrEnum):
    """State of any subsequent finding verification."""

    PENDING = "pending"
    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    NOT_IMPLEMENTED = "not_implemented"


class ScanStatus(StrEnum):
    """Current state of the overall scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
