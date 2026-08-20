"""Enumerations shared across SentinelLLM contracts."""

from enum import StrEnum


class AttackCategory(StrEnum):
    """High-level attack categories enabled for a scan."""

    PROMPT_INJECTION = "prompt_injection"
    SENSITIVE_INFORMATION_DISCLOSURE = "sensitive_information_disclosure"
    INSECURE_OUTPUT_HANDLING = "insecure_output_handling"
    EXCESSIVE_AGENCY = "excessive_agency"


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


class JudgeOutcome(StrEnum):
    """Conclusion produced by an attack judge."""

    FAILED = "failed"
    PARTIAL = "partial"
    SUCCESSFUL = "successful"
    INCONCLUSIVE = "inconclusive"


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
