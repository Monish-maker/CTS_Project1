"""Attack judge boundary and deterministic implementation."""

from abc import ABC, abstractmethod

from sentinelllm.core.enums import AdaptiveDecisionType, JudgeOutcome
from sentinelllm.core.models import AttackPlan, AttackResult, JudgeResult, Observation
from sentinelllm.llm.provider import (
    DeterministicLLMProvider,
    LLMProvider,
    LLMProviderError,
    StructuredLLMRequest,
)


class AttackJudge(ABC):
    """Interprets raw attack evidence against a planned objective."""

    @abstractmethod
    async def judge(
        self, plan: AttackPlan, result: AttackResult, observation: Observation | None = None
    ) -> JudgeResult:
        """Return a bounded judgment based on implemented evaluation logic."""
        raise NotImplementedError


# Signals that indicate the target actually disclosed or executed something unsafe,
# as opposed to merely echoing the scanner's own probe text back.
_CONTENT_EVIDENCE_SIGNALS = ("security_keyword", "xss_payload")


class DefaultAttackJudge(AttackJudge):
    """Apply deterministic, reviewable evidence rules."""

    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.provider = provider or DeterministicLLMProvider()

    async def judge(
        self, plan: AttackPlan, result: AttackResult, observation: Observation | None = None
    ) -> JudgeResult:
        """Judge expected indicators while requiring verification for strong signals."""
        if result.errors:
            return JudgeResult(
                JudgeOutcome.ERROR,
                1.0,
                "; ".join(result.errors),
                job_id=result.job_id,
                recommended_action=AdaptiveDecisionType.SWITCH_STRATEGY,
            )
        response = (result.response or "").lower()
        expected = result.response_metadata.get("expected_signals", plan.expected_indicators)
        matched = tuple(
            str(indicator) for indicator in expected if str(indicator).lower() in response
        )
        content_signals = tuple(
            signal
            for signal in (observation.signals if observation else ())
            if signal in _CONTENT_EVIDENCE_SIGNALS
        )
        references = result.evidence
        if content_signals:
            return JudgeResult(
                JudgeOutcome.POTENTIAL_SUCCESS,
                min(0.95, 0.7 + 0.1 * len(content_signals)),
                "Response contained unsafe disclosed or executable content: "
                f"{', '.join(content_signals)}; verification is required",
                references,
                result.job_id,
                (*matched, *content_signals),
                AdaptiveDecisionType.VERIFY,
            )
        if matched:
            return JudgeResult(
                JudgeOutcome.POTENTIAL_SUCCESS,
                min(0.95, 0.65 + 0.1 * len(matched)),
                "Response matched controlled success indicators; verification is required",
                references,
                result.job_id,
                matched,
                AdaptiveDecisionType.VERIFY,
            )
        if result.http_status is not None and result.http_status >= 500:
            return JudgeResult(
                JudgeOutcome.PARTIAL,
                0.45,
                "Attack produced an abnormal server response",
                references,
                result.job_id,
                (),
                AdaptiveDecisionType.REFINE_STRATEGY,
            )
        assisted = await self._provider_judgment(plan, result)
        if assisted is not None:
            return assisted
        return JudgeResult(
            JudgeOutcome.FAILED,
            0.75,
            "No planned success criteria were observed",
            references,
            result.job_id,
            (),
            AdaptiveDecisionType.SWITCH_STRATEGY,
        )

    async def _provider_judgment(
        self, plan: AttackPlan, result: AttackResult
    ) -> JudgeResult | None:
        """Interpret ambiguous evidence without allowing fabricated evidence references."""
        if isinstance(self.provider, DeterministicLLMProvider):
            return None
        allowed = (
            JudgeOutcome.FAILED,
            JudgeOutcome.PARTIAL,
            JudgeOutcome.POTENTIAL_SUCCESS,
            JudgeOutcome.INCONCLUSIVE,
        )
        try:
            output = await self.provider.complete(
                StructuredLLMRequest(
                    task="Classify observed response evidence against success criteria",
                    context={
                        "category": plan.category.value,
                        "objective": plan.objective,
                        "success_criteria": plan.success_criteria,
                        "http_status": result.http_status,
                        "response_excerpt": (result.response or "")[:4000],
                        "evidence_references": result.evidence,
                    },
                    allowed_values={"outcome": tuple(item.value for item in allowed)},
                    required_fields=("outcome", "confidence", "reason"),
                )
            )
            if output.get("fallback"):
                return None
            confidence = float(output["confidence"])
            reason = str(output["reason"]).strip()
            if not 0.0 <= confidence <= 1.0 or not reason or len(reason) > 1000:
                raise ValueError("provider judgment is outside bounded fields")
            outcome = JudgeOutcome(str(output["outcome"]))
            recommendation = (
                AdaptiveDecisionType.VERIFY
                if outcome == JudgeOutcome.POTENTIAL_SUCCESS
                else AdaptiveDecisionType.REFINE_STRATEGY
                if outcome == JudgeOutcome.PARTIAL
                else AdaptiveDecisionType.SWITCH_STRATEGY
            )
            return JudgeResult(
                outcome,
                confidence,
                f"Provider-assisted interpretation: {reason}",
                result.evidence,
                result.job_id,
                (),
                recommendation,
            )
        except (LLMProviderError, ValueError, KeyError, TypeError):
            return None
