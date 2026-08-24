"""Finding verification boundary."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from uuid import uuid4

from sentinelllm.core.enums import VerificationStatus
from sentinelllm.core.models import Finding


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Result of verifying one potential finding."""

    finding_id: str
    status: VerificationStatus
    reason: str
    verification_id: str = ""
    job_ids: tuple[str, ...] = ()
    evidence_references: tuple[str, ...] = ()


class VerificationComponent(ABC):
    """Re-tests a potential finding using future controlled logic."""

    @abstractmethod
    async def verify(self, finding: Finding) -> VerificationResult:
        """Verify a finding without modifying its original evidence."""
        raise NotImplementedError


class DefaultVerificationComponent(VerificationComponent):
    """Require independently recorded reproduction evidence."""

    async def verify(self, finding: Finding) -> VerificationResult:
        """Confirm only candidates correlated to at least two distinct attack jobs."""
        unique_jobs = tuple(dict.fromkeys(finding.job_ids))
        unique_strategies = tuple(dict.fromkeys(finding.strategy_ids))
        verified = len(unique_jobs) >= 2 and len(unique_strategies) >= 2 and bool(finding.evidence)
        return VerificationResult(
            finding_id=finding.finding_id,
            status=VerificationStatus.VERIFIED if verified else VerificationStatus.NOT_VERIFIED,
            reason=(
                "Behavior reproduced by distinct controlled jobs and strategies"
                if verified
                else "Insufficient independent job, strategy, or evidence reproduction"
            ),
            verification_id=f"VR-{uuid4().hex[:12]}",
            job_ids=unique_jobs,
            evidence_references=finding.evidence,
        )
