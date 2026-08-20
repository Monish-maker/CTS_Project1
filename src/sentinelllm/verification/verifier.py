"""Verification boundary and placeholder."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from sentinelllm.core.enums import VerificationStatus
from sentinelllm.core.errors import FeatureNotImplementedError
from sentinelllm.core.models import Finding


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Result of verifying one potential finding."""

    finding_id: str
    status: VerificationStatus
    reason: str


class VerificationComponent(ABC):
    """Re-tests a potential finding using future controlled logic."""

    @abstractmethod
    async def verify(self, finding: Finding) -> VerificationResult:
        """Verify a finding without modifying its original evidence."""
        raise NotImplementedError


class DefaultVerificationComponent(VerificationComponent):
    """Clearly unimplemented production verification component."""

    async def verify(self, finding: Finding) -> VerificationResult:
        """Raise rather than declaring a finding verified."""
        raise FeatureNotImplementedError("Finding verification is not implemented in Phase 1")
