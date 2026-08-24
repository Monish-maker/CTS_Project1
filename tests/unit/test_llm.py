"""Tests for provider-neutral structured LLM decisions and safe fallbacks."""

import asyncio

import pytest

from sentinelllm.attacks.agent import DefaultAttackAgent
from sentinelllm.core.enums import AdaptiveDecisionType, AttackCategory, JudgeOutcome, RiskLevel
from sentinelllm.core.models import (
    AttackHypothesis,
    AttackPlan,
    AttackResult,
    JudgeResult,
    LLMConfiguration,
    Observation,
    ScanConfiguration,
    TargetProfile,
)
from sentinelllm.judging.judge import DefaultAttackJudge
from sentinelllm.llm.provider import (
    AnthropicProvider,
    AzureOpenAIProvider,
    LLMProvider,
    OpenAICompatibleProvider,
    StructuredLLMRequest,
    build_llm_provider,
    validate_structured_output,
)


class InvalidProvider(LLMProvider):
    async def complete(self, request: StructuredLLMRequest) -> dict[str, object]:
        raise ValueError("malformed structured output")


class TaskAwareProvider(LLMProvider):
    async def complete(self, request: StructuredLLMRequest) -> dict[str, object]:
        if request.task.startswith("Formulate"):
            return {
                "description": "The target may follow untrusted retrieved instructions.",
                "objective": "Establish whether retrieval changes instruction priority.",
                "expected_signal": "A controlled marker appears after retrieval.",
            }
        if request.task.startswith("Classify"):
            return {
                "outcome": "partial",
                "confidence": 0.6,
                "reason": "The response changed materially but did not match the marker.",
            }
        return {"fallback": True, "reason": "unsupported test task"}


def test_structured_output_rejects_missing_and_unbounded_values() -> None:
    request = StructuredLLMRequest(
        task="select",
        context={},
        allowed_values={"decision": ("stop",)},
        required_fields=("decision", "reason"),
    )
    with pytest.raises(ValueError, match="missing"):
        validate_structured_output(request, {"decision": "stop"})
    with pytest.raises(ValueError, match="outside"):
        validate_structured_output(request, {"decision": "execute_shell", "reason": "bad"})


def test_invalid_provider_output_falls_back_without_crashing_scan() -> None:
    plan = AttackPlan(
        attack_id="AT-1",
        category=AttackCategory.PROMPT_INJECTION,
        owasp_mapping="LLM01:2026",
        objective="test",
        preconditions=(),
        strategy="baseline",
        expected_indicators=("marker",),
        risk_level=RiskLevel.MEDIUM,
        strategy_id="prompt_injection.baseline",
    )
    hypothesis = AttackHypothesis(
        "HY-1",
        AttackCategory.PROMPT_INJECTION,
        "test",
        "test",
        "marker",
    )
    observation = Observation("OB-1", "AJ-1", "no signal", strategy_id=plan.strategy_id)
    judgment = JudgeResult(JudgeOutcome.FAILED, 0.8, "no signal", job_id="AJ-1")
    agent = DefaultAttackAgent(provider=InvalidProvider())

    decision, _, next_job = asyncio.run(
        agent.adapt(
            plan,
            ScanConfiguration(target_url="https://example.test"),
            TargetProfile(target_url="https://example.test"),
            hypothesis,
            observation,
            judgment,
            {plan.strategy_id},
            1,
        )
    )

    assert decision.decision is AdaptiveDecisionType.SWITCH_STRATEGY
    assert "provider fallback" in decision.reason
    assert next_job is not None


def test_provider_can_refine_hypothesis_metadata() -> None:
    plan = AttackPlan(
        "AT-hypothesis",
        AttackCategory.PROMPT_INJECTION,
        "LLM01:2026",
        "initial objective",
        (),
        "retrieval test",
        ("marker",),
        RiskLevel.HIGH,
        strategy_id="prompt_injection.context",
    )
    agent = DefaultAttackAgent(provider=TaskAwareProvider())
    initial = agent.create_hypothesis(plan)

    refined = asyncio.run(agent.refine_hypothesis(plan, initial))

    assert refined.hypothesis_id == initial.hypothesis_id
    assert "retrieved instructions" in refined.description
    assert "instruction priority" in refined.objective


def test_provider_assisted_judge_cannot_fabricate_evidence_references() -> None:
    plan = AttackPlan(
        "AT-judge",
        AttackCategory.PROMPT_INJECTION,
        "LLM01:2026",
        "test",
        (),
        "context test",
        ("marker",),
        RiskLevel.HIGH,
    )
    result = AttackResult(
        "AJ-judge",
        200,
        "materially different response",
        evidence=("EV-observed",),
    )

    judgment = asyncio.run(DefaultAttackJudge(TaskAwareProvider()).judge(plan, result))

    assert judgment.outcome is JudgeOutcome.PARTIAL
    assert judgment.confidence == 0.6
    assert judgment.evidence_references == ("EV-observed",)
    assert judgment.recommended_action is AdaptiveDecisionType.REFINE_STRATEGY


def test_named_provider_adapters_use_expected_protocol_envelopes() -> None:
    request = StructuredLLMRequest("select", {"signal": "test"}, {}, ("decision",))
    configuration = LLMConfiguration(
        provider="openai_compatible",
        model="test-model",
        endpoint="https://provider.test/v1/chat/completions",
    )
    openai = OpenAICompatibleProvider(configuration)
    openai_payload = openai._request_payload(request)
    assert openai_payload["messages"][1]["role"] == "user"
    assert openai._extract_candidate(
        {"choices": [{"message": {"content": '{"decision":"stop"}'}}]}
    ) == {"decision": "stop"}

    anthropic = AnthropicProvider(configuration)
    anthropic_payload = anthropic._request_payload(request)
    assert anthropic_payload["max_tokens"] == 1024
    assert anthropic._extract_candidate(
        {"content": [{"type": "text", "text": '{"decision":"stop"}'}]}
    ) == {"decision": "stop"}

    azure = AzureOpenAIProvider(configuration)
    assert azure._authentication_headers("secret") == {"api-key": "secret"}
    assert anthropic._authentication_headers("secret")["anthropic-version"] == "2023-06-01"


@pytest.mark.parametrize(
    ("provider_name", "expected_type"),
    [
        ("openai_compatible", OpenAICompatibleProvider),
        ("azure_openai", AzureOpenAIProvider),
        ("anthropic", AnthropicProvider),
    ],
)
def test_provider_factory_selects_dedicated_adapter(
    provider_name: str, expected_type: type[LLMProvider]
) -> None:
    provider = build_llm_provider(
        LLMConfiguration(provider=provider_name, endpoint="https://provider.test/api")
    )
    assert isinstance(provider, expected_type)
