"""Response-driven attack job generation boundary."""

from abc import ABC, abstractmethod
from uuid import uuid4

from sentinelllm.core.enums import AdaptiveDecisionType, HypothesisStatus, JudgeOutcome
from sentinelllm.core.models import (
    AdaptationDecision,
    AttackHypothesis,
    AttackJob,
    AttackPlan,
    JudgeResult,
    Observation,
    ScanConfiguration,
    TargetProfile,
)
from sentinelllm.llm.provider import (
    DeterministicLLMProvider,
    LLMProvider,
    LLMProviderError,
    StructuredLLMRequest,
)
from sentinelllm.planning.strategies import StrategyRegistry, build_default_registry


class AttackAgent(ABC):
    """Converts approved attack plans into individual execution jobs."""

    @abstractmethod
    async def create_jobs(
        self, plans: tuple[AttackPlan, ...], configuration: ScanConfiguration
    ) -> tuple[AttackJob, ...]:
        """Create jobs without generating payloads or executing requests."""
        raise NotImplementedError


class DefaultAttackAgent(AttackAgent):
    """Generate initial and response-driven follow-up jobs from registered strategies."""

    def __init__(
        self,
        registry: StrategyRegistry | None = None,
        provider: LLMProvider | None = None,
    ) -> None:
        self.registry = registry or build_default_registry()
        self.provider = provider or DeterministicLLMProvider()

    async def create_jobs(
        self, plans: tuple[AttackPlan, ...], configuration: ScanConfiguration
    ) -> tuple[AttackJob, ...]:
        """Create one independently executable initial job per approved plan."""
        return tuple(self._job(plan, configuration, plan.strategy_id, 1) for plan in plans)

    def create_hypothesis(self, plan: AttackPlan) -> AttackHypothesis:
        return AttackHypothesis(
            hypothesis_id=f"HY-{uuid4().hex[:12]}",
            category=plan.category,
            description=f"Target may exhibit {plan.category.value.replace('_', ' ')}",
            objective=plan.objective,
            expected_signal=", ".join(plan.expected_indicators),
            status=HypothesisStatus.ACTIVE,
        )

    async def refine_hypothesis(
        self, plan: AttackPlan, hypothesis: AttackHypothesis
    ) -> AttackHypothesis:
        """Optionally formulate auditable hypothesis metadata through the provider."""
        if isinstance(self.provider, DeterministicLLMProvider):
            return hypothesis
        try:
            output = await self.provider.complete(
                StructuredLLMRequest(
                    task="Formulate a concise security-testing hypothesis",
                    context={
                        "category": plan.category.value,
                        "strategy": plan.strategy,
                        "objective": plan.objective,
                        "expected_indicators": plan.expected_indicators,
                    },
                    allowed_values={},
                    required_fields=("description", "objective", "expected_signal"),
                )
            )
            if output.get("fallback"):
                return hypothesis
            values = {
                field: str(output[field]).strip()
                for field in ("description", "objective", "expected_signal")
            }
            if any(not value or len(value) > 500 for value in values.values()):
                raise ValueError("hypothesis fields must contain 1 to 500 characters")
            return AttackHypothesis(
                hypothesis.hypothesis_id,
                hypothesis.category,
                values["description"],
                values["objective"],
                values["expected_signal"],
                hypothesis.status,
                hypothesis.confidence,
                hypothesis.evidence_references,
            )
        except (LLMProviderError, ValueError, KeyError, TypeError):
            return hypothesis

    async def adapt(
        self,
        plan: AttackPlan,
        configuration: ScanConfiguration,
        profile: TargetProfile,
        hypothesis: AttackHypothesis,
        observation: Observation,
        judgment: JudgeResult,
        attempted_strategy_ids: set[str],
        iteration: int,
    ) -> tuple[AdaptationDecision, AttackHypothesis, AttackJob | None]:
        """Select the next action from actual observations and bounded judge feedback."""
        next_strategy_id: str | None = None
        next_job: AttackJob | None = None
        evidence = observation.evidence_references
        if judgment.outcome in {JudgeOutcome.SUCCESSFUL, JudgeOutcome.POTENTIAL_SUCCESS}:
            decision_type = AdaptiveDecisionType.VERIFY
            status = HypothesisStatus.SUPPORTED
            confidence = max(hypothesis.confidence, judgment.confidence)
            candidates = [
                item
                for item in self.registry.rank(plan.category, profile, attempted_strategy_ids)
                if item.test_type == "verification"
            ]
        elif judgment.outcome == JudgeOutcome.PARTIAL:
            decision_type = AdaptiveDecisionType.REFINE_STRATEGY
            status = HypothesisStatus.SUPPORTED
            confidence = max(hypothesis.confidence, judgment.confidence * 0.8)
            candidates = list(self.registry.rank(plan.category, profile, attempted_strategy_ids))
        elif judgment.outcome == JudgeOutcome.FAILED:
            decision_type = AdaptiveDecisionType.SWITCH_STRATEGY
            status = HypothesisStatus.WEAKENED
            confidence = hypothesis.confidence * 0.5
            candidates = list(self.registry.rank(plan.category, profile, attempted_strategy_ids))
        else:
            decision_type = AdaptiveDecisionType.SWITCH_STRATEGY
            status = HypothesisStatus.WEAKENED
            confidence = hypothesis.confidence
            candidates = list(self.registry.rank(plan.category, profile, attempted_strategy_ids))

        if iteration >= configuration.maximum_attack_iterations or not candidates:
            decision_type = AdaptiveDecisionType.STOP
            candidates = []
            if status == HypothesisStatus.WEAKENED:
                status = HypothesisStatus.ABANDONED
        provider_reason = ""
        if candidates and not isinstance(self.provider, DeterministicLLMProvider):
            allowed_decisions = tuple(item.value for item in AdaptiveDecisionType)
            allowed_strategies = tuple(item.strategy_id for item in candidates)
            try:
                provider_output = await self.provider.complete(
                    StructuredLLMRequest(
                        task="Select the next bounded security-testing action",
                        context={
                            "category": plan.category.value,
                            "observation": observation.summary,
                            "signals": observation.signals,
                            "judge_outcome": judgment.outcome.value,
                            "judge_confidence": judgment.confidence,
                            "hypothesis_status": status.value,
                            "attempted_strategies": sorted(attempted_strategy_ids),
                            "remaining_iterations": max(
                                configuration.maximum_attack_iterations - iteration, 0
                            ),
                        },
                        allowed_values={
                            "decision": allowed_decisions,
                            "next_strategy_id": allowed_strategies,
                        },
                        required_fields=("decision", "next_strategy_id", "reason"),
                    )
                )
                if not provider_output.get("fallback"):
                    decision_type = AdaptiveDecisionType(str(provider_output["decision"]))
                    selected = str(provider_output["next_strategy_id"])
                    candidates.sort(key=lambda item: item.strategy_id != selected)
                    provider_reason = f"; provider: {provider_output['reason']}"
            except (LLMProviderError, ValueError, KeyError, TypeError) as error:
                provider_reason = f"; provider fallback: {type(error).__name__}: {error}"
        if candidates:
            next_strategy_id = candidates[0].strategy_id
            next_job = self._job(plan, configuration, next_strategy_id, iteration + 1)
        updated = AttackHypothesis(
            hypothesis.hypothesis_id,
            hypothesis.category,
            hypothesis.description,
            hypothesis.objective,
            hypothesis.expected_signal,
            status,
            min(confidence, 1.0),
            tuple(dict.fromkeys((*hypothesis.evidence_references, *evidence))),
        )
        decision = AdaptationDecision(
            decision_id=f"AD-{uuid4().hex[:12]}",
            iteration=iteration,
            decision=decision_type,
            previous_strategy_id=observation.strategy_id or plan.strategy_id,
            next_strategy_id=next_strategy_id,
            hypothesis_id=hypothesis.hypothesis_id,
            evidence_references=evidence,
            confidence=judgment.confidence,
            reason=f"{judgment.outcome.value}: {observation.summary}{provider_reason}",
            triggering_job_id=observation.job_id,
            next_job_id=next_job.job_id if next_job else None,
        )
        return decision, updated, next_job

    def _job(
        self, plan: AttackPlan, configuration: ScanConfiguration, strategy_id: str, iteration: int
    ) -> AttackJob:
        strategy = self.registry.get(strategy_id)
        marker = strategy.expected_signals[-1]
        endpoint = plan.endpoint or configuration.target_url
        prompt = strategy.prompt_template
        return AttackJob(
            job_id=f"AJ-{uuid4().hex[:12]}",
            scan_id=configuration.scan_id,
            attack_id=plan.attack_id,
            iteration=iteration,
            request={
                "method": plan.method,
                "url": endpoint,
                "json": self._request_json(plan, configuration, prompt),
            },
            metadata={
                "category": plan.category.value,
                "strategy_id": strategy.strategy_id,
                "strategy": strategy.name,
                "objective": strategy.objective,
                "test_type": strategy.test_type,
                "expected_signals": strategy.expected_signals,
                "marker": marker,
                "parameter": plan.parameter,
            },
        )

    def _request_json(
        self, plan: AttackPlan, configuration: ScanConfiguration, prompt: str
    ) -> dict[str, object]:
        if configuration.target_request.format == "anthropic_messages":
            return {
                "model": configuration.target_request.model or "claude-3-5-sonnet-latest",
                "max_tokens": configuration.target_request.max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
        if configuration.target_request.format == "gemini_generate_content":
            return {
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": configuration.target_request.max_tokens},
            }
        return {plan.parameter: prompt}
