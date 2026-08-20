"""Final evaluator boundary and placeholder."""

from abc import ABC, abstractmethod

from sentinelllm.core.errors import FeatureNotImplementedError
from sentinelllm.core.models import AttackPlan, AttackResult, Finding, JudgeResult


class FinalEvaluator(ABC):
    """Classifies corroborated judged results into security findings."""

    @abstractmethod
    async def evaluate(
        self,
        plan: AttackPlan,
        result: AttackResult,
        judgment: JudgeResult,
    ) -> tuple[Finding, ...]:
        """Create findings only from implemented evaluation rules."""
        raise NotImplementedError


class DefaultFinalEvaluator(FinalEvaluator):
    """Clearly unimplemented production final evaluator."""

    async def evaluate(
        self,
        plan: AttackPlan,
        result: AttackResult,
        judgment: JudgeResult,
    ) -> tuple[Finding, ...]:
        """Raise rather than emitting a security finding."""
        raise FeatureNotImplementedError("Final evaluation is not implemented in Phase 1")
