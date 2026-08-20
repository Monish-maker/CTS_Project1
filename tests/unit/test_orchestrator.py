"""Tests for dependency-injected Phase 1 orchestration."""

from sentinelllm.core.enums import ScanStatus
from sentinelllm.core.models import ScanConfiguration
from sentinelllm.orchestrator.scan_orchestrator import ScanOrchestrator
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


def test_orchestrator_starts_scan_through_injected_history_store() -> None:
    history_store = MockHistoryStore()
    orchestrator = ScanOrchestrator(
        connector=MockTargetConnector(),
        discovery=MockDiscoveryAgent(),
        planner=MockAttackPlanner(),
        attack_agent=MockAttackAgent(),
        executor=MockAttackExecutor(),
        judge=MockAttackJudge(),
        verifier=MockVerificationComponent(),
        evaluator=MockFinalEvaluator(),
        history=history_store,
        reporter=MockReportGenerator(),
    )
    configuration = ScanConfiguration(target_url="https://example.test", scan_id="scan-test")

    scan_history = orchestrator.start(configuration)

    assert scan_history.status is ScanStatus.PENDING
    assert history_store.started_configurations == [configuration]
