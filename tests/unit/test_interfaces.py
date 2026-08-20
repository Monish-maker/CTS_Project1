"""Tests that test doubles meet the abstract component contracts."""

from sentinelllm.attacks.agent import AttackAgent
from sentinelllm.attacks.executor import AttackExecutor
from sentinelllm.connector.base import TargetConnector
from sentinelllm.discovery.base import DiscoveryAgent
from sentinelllm.evaluation.evaluator import FinalEvaluator
from sentinelllm.history.store import HistoryStore
from sentinelllm.judging.judge import AttackJudge
from sentinelllm.planning.attack_planner import AttackPlanner
from sentinelllm.reporting.base import ReportGenerator
from sentinelllm.verification.verifier import VerificationComponent
from tests.mocks import (
    MockAttackAgent,
    MockAttackExecutor,
    MockAttackJudge,
    MockAttackPlanner,
    MockDiscoveryAgent,
    MockFinalEvaluator,
    MockHistoryStore,
    MockReportGenerator,
    MockTargetConnector,
    MockVerificationComponent,
)


def test_mock_implementations_satisfy_contracts() -> None:
    assert isinstance(MockTargetConnector(), TargetConnector)
    assert isinstance(MockDiscoveryAgent(), DiscoveryAgent)
    assert isinstance(MockAttackPlanner(), AttackPlanner)
    assert isinstance(MockAttackAgent(), AttackAgent)
    assert isinstance(MockAttackExecutor(), AttackExecutor)
    assert isinstance(MockAttackJudge(), AttackJudge)
    assert isinstance(MockVerificationComponent(), VerificationComponent)
    assert isinstance(MockFinalEvaluator(), FinalEvaluator)
    assert isinstance(MockHistoryStore(), HistoryStore)
    assert isinstance(MockReportGenerator(), ReportGenerator)
