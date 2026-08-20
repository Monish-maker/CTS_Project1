"""Central composition root for the future scanner workflow."""

import logging

from sentinelllm.attacks.agent import AttackAgent
from sentinelllm.attacks.executor import AttackExecutor
from sentinelllm.connector.base import TargetConnector
from sentinelllm.core.models import ScanConfiguration, ScanHistory
from sentinelllm.discovery.base import DiscoveryAgent
from sentinelllm.evaluation.evaluator import FinalEvaluator
from sentinelllm.history.store import HistoryStore
from sentinelllm.judging.judge import AttackJudge
from sentinelllm.planning.attack_planner import AttackPlanner
from sentinelllm.reporting.base import ReportGenerator
from sentinelllm.verification.verifier import VerificationComponent


class ScanOrchestrator:
    """Coordinates component boundaries without embedding component-specific logic."""

    def __init__(
        self,
        connector: TargetConnector,
        discovery: DiscoveryAgent,
        planner: AttackPlanner,
        attack_agent: AttackAgent,
        executor: AttackExecutor,
        judge: AttackJudge,
        verifier: VerificationComponent,
        evaluator: FinalEvaluator,
        history: HistoryStore,
        reporter: ReportGenerator,
    ) -> None:
        self._connector = connector
        self._discovery = discovery
        self._planner = planner
        self._attack_agent = attack_agent
        self._executor = executor
        self._judge = judge
        self._verifier = verifier
        self._evaluator = evaluator
        self._history = history
        self._reporter = reporter
        self._logger = logging.getLogger(__name__)

    def start(self, configuration: ScanConfiguration) -> ScanHistory:
        """Record a pending scan; the pipeline is intentionally deferred beyond Phase 1."""
        self._logger.info("scan initialized scan_id=%s", configuration.scan_id)
        return self._history.start_scan(configuration)
