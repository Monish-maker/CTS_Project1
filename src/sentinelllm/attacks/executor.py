"""Attack execution boundary."""

from abc import ABC, abstractmethod

from sentinelllm.connector.base import TargetConnector
from sentinelllm.core.errors import FeatureNotImplementedError
from sentinelllm.core.models import AttackJob, AttackResult


class AttackExecutor(ABC):
    """Executes an approved attack job through the target connector."""

    @abstractmethod
    async def execute(self, job: AttackJob, connector: TargetConnector) -> AttackResult:
        """Return raw execution evidence without judging it."""
        raise NotImplementedError


class DefaultAttackExecutor(AttackExecutor):
    """Clearly unimplemented production attack executor."""

    async def execute(self, job: AttackJob, connector: TargetConnector) -> AttackResult:
        """Raise rather than sending unimplemented attack traffic."""
        raise FeatureNotImplementedError("Attack execution is not implemented in Phase 1")
