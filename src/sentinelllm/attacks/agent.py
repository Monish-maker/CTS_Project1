"""Attack job generation boundary."""

from abc import ABC, abstractmethod

from sentinelllm.core.errors import FeatureNotImplementedError
from sentinelllm.core.models import AttackJob, AttackPlan, ScanConfiguration


class AttackAgent(ABC):
    """Converts approved attack plans into individual execution jobs."""

    @abstractmethod
    async def create_jobs(
        self, plans: tuple[AttackPlan, ...], configuration: ScanConfiguration
    ) -> tuple[AttackJob, ...]:
        """Create jobs without generating payloads or executing requests."""
        raise NotImplementedError


class DefaultAttackAgent(AttackAgent):
    """Clearly unimplemented production attack agent."""

    async def create_jobs(
        self, plans: tuple[AttackPlan, ...], configuration: ScanConfiguration
    ) -> tuple[AttackJob, ...]:
        """Raise rather than creating autonomous attack jobs."""
        raise FeatureNotImplementedError("Attack job generation is not implemented in Phase 1")
