"""Attack planner boundary and placeholder."""

from abc import ABC, abstractmethod

from sentinelllm.core.errors import FeatureNotImplementedError
from sentinelllm.core.models import AttackPlan, ScanConfiguration, TargetProfile


class AttackPlanner(ABC):
    """Selects and structures applicable, authorized security tests."""

    @abstractmethod
    async def plan(self, profile: TargetProfile, configuration: ScanConfiguration) -> tuple[AttackPlan, ...]:
        """Return plans without executing them."""
        raise NotImplementedError


class DefaultAttackPlanner(AttackPlanner):
    """Clearly unimplemented production attack planner."""

    async def plan(self, profile: TargetProfile, configuration: ScanConfiguration) -> tuple[AttackPlan, ...]:
        """Raise rather than generating placeholder attack strategies."""
        raise FeatureNotImplementedError("Attack planning is not implemented in Phase 1")
