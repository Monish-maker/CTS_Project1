"""Edge-case tests for bounded adaptation, transport failures, and verification."""

import asyncio

import pytest

from sentinelllm.attacks.agent import DefaultAttackAgent
from sentinelllm.attacks.executor import DefaultAttackExecutor
from sentinelllm.connector.base import TargetConnector, TargetResponse
from sentinelllm.connector.http import HttpTargetConnector
from sentinelllm.core.enums import (
    AdaptiveDecisionType,
    AttackCategory,
    HypothesisStatus,
    JudgeOutcome,
    RiskLevel,
    ScanStatus,
    VerificationStatus,
)
from sentinelllm.core.models import (
    AttackHypothesis,
    AttackJob,
    AttackPlan,
    Finding,
    JudgeResult,
    Observation,
    ScanConfiguration,
    TargetProfile,
)
from sentinelllm.discovery.discovery_agent import DefaultDiscoveryAgent
from sentinelllm.evaluation.evaluator import DefaultFinalEvaluator
from sentinelllm.history.store import InMemoryHistoryStore
from sentinelllm.judging.judge import DefaultAttackJudge
from sentinelllm.orchestrator.scan_orchestrator import ScanOrchestrator
from sentinelllm.planning.attack_planner import DefaultAttackPlanner
from sentinelllm.reporting.bundle import ReportBundleGenerator
from sentinelllm.verification.verifier import DefaultVerificationComponent


def _plan() -> AttackPlan:
    return AttackPlan(
        attack_id="AT-edge",
        category=AttackCategory.PROMPT_INJECTION,
        owasp_mapping="LLM01:2026",
        objective="test boundaries",
        preconditions=(),
        strategy="baseline",
        expected_indicators=("marker",),
        risk_level=RiskLevel.HIGH,
        strategy_id="prompt_injection.baseline",
    )


def _hypothesis() -> AttackHypothesis:
    return AttackHypothesis(
        "HY-edge",
        AttackCategory.PROMPT_INJECTION,
        "boundary may change",
        "test boundaries",
        "marker",
        HypothesisStatus.ACTIVE,
    )


def test_weak_signal_refines_strategy() -> None:
    agent = DefaultAttackAgent()
    decision, updated, next_job = asyncio.run(
        agent.adapt(
            _plan(),
            ScanConfiguration(target_url="https://example.test"),
            TargetProfile(target_url="https://example.test"),
            _hypothesis(),
            Observation("OB-edge", "AJ-edge", "server error"),
            JudgeResult(JudgeOutcome.PARTIAL, 0.45, "weak signal", job_id="AJ-edge"),
            {"prompt_injection.baseline"},
            1,
        )
    )

    assert decision.decision is AdaptiveDecisionType.REFINE_STRATEGY
    assert updated.status is HypothesisStatus.SUPPORTED
    assert next_job is not None


def test_exhausted_iteration_budget_abandons_weakened_hypothesis() -> None:
    agent = DefaultAttackAgent()
    decision, updated, next_job = asyncio.run(
        agent.adapt(
            _plan(),
            ScanConfiguration(target_url="https://example.test", maximum_attack_iterations=1),
            TargetProfile(target_url="https://example.test"),
            _hypothesis(),
            Observation("OB-edge", "AJ-edge", "no signal"),
            JudgeResult(JudgeOutcome.FAILED, 0.8, "failed", job_id="AJ-edge"),
            {"prompt_injection.baseline"},
            1,
        )
    )

    assert decision.decision is AdaptiveDecisionType.STOP
    assert updated.status is HypothesisStatus.ABANDONED
    assert next_job is None


class TimeoutConnector(HttpTargetConnector):
    def _send_sync(self, request: dict[str, object], attempt: int) -> TargetResponse:
        raise TimeoutError


def test_timeout_retries_are_bounded_by_actual_request_budget() -> None:
    connector = TimeoutConnector(retries=5, maximum_requests=1)

    response = asyncio.run(connector.send({"url": "https://example.test"}))

    assert response.status_code is None
    assert response.metadata["error"] == "connector request budget exhausted"


class CancelledConnector(TargetConnector):
    async def send(self, request: dict[str, object]) -> TargetResponse:
        raise asyncio.CancelledError


def test_scan_cancellation_is_not_converted_to_an_attack_error() -> None:
    executor = DefaultAttackExecutor()
    job = AttackJob("AJ-cancel", "scan", "attack", 1)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(executor.execute(job, CancelledConnector()))


def test_single_job_candidate_is_not_verified() -> None:
    finding = Finding(
        "F-edge",
        "Candidate",
        "description",
        RiskLevel.HIGH,
        0.8,
        "LLM01:2026",
        "AT-edge",
        ("EV-edge",),
        "impact",
        "remediation",
        job_ids=("AJ-one",),
        strategy_ids=("prompt_injection.baseline",),
    )

    result = asyncio.run(DefaultVerificationComponent().verify(finding))

    assert result.status is VerificationStatus.NOT_VERIFIED


class WaitingConnector(TargetConnector):
    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def send(self, request: dict[str, object]) -> TargetResponse:
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


def test_cancelled_scan_persists_partial_history_and_reports(tmp_path: object) -> None:
    async def scenario() -> None:
        from pathlib import Path

        output = Path(str(tmp_path))
        connector = WaitingConnector()
        store = InMemoryHistoryStore()
        orchestrator = ScanOrchestrator(
            connector,
            DefaultDiscoveryAgent(),
            DefaultAttackPlanner(),
            DefaultAttackAgent(),
            DefaultAttackExecutor(),
            DefaultAttackJudge(),
            DefaultVerificationComponent(),
            DefaultFinalEvaluator(),
            store,
            ReportBundleGenerator(),
        )
        configuration = ScanConfiguration(
            target_url="https://example.test",
            dry_run=False,
            reporting_output_directory=str(output),
        )
        task = asyncio.create_task(orchestrator.run(configuration))
        await connector.started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        history = store.get_scan(configuration.scan_id)
        assert history is not None
        assert history.status is ScanStatus.CANCELLED
        assert (output / configuration.scan_id / "sentinelllm_attack_report.json").exists()

    asyncio.run(scenario())
