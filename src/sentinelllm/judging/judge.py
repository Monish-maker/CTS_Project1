"""Attack judge boundary and placeholder."""

from abc import ABC, abstractmethod

from sentinelllm.core.errors import FeatureNotImplementedError
from sentinelllm.core.models import AttackPlan, AttackResult, JudgeResult


class AttackJudge(ABC):
    """Interprets raw attack evidence against a planned objective."""

    @abstractmethod
    async def judge(self, plan: AttackPlan, result: AttackResult) -> JudgeResult:
        """Return a bounded judgment based on implemented evaluation logic."""
        raise NotImplementedError


class DefaultAttackJudge(AttackJudge):
    """Clearly unimplemented production attack judge."""

    async def judge(self, plan: AttackPlan, result: AttackResult) -> JudgeResult:
        """Raise rather than claiming a security outcome."""
        raise FeatureNotImplementedError("Attack judging is not implemented in Phase 1")
