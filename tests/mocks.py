"""Test-only implementations of SentinelLLM component contracts."""

from pathlib import Path

from sentinelllm.attacks.agent import AttackAgent
from sentinelllm.attacks.executor import AttackExecutor
from sentinelllm.connector.base import TargetConnector, TargetResponse
from sentinelllm.core.enums import JudgeOutcome, VerificationStatus
from sentinelllm.core.models import (
    AttackJob,
    AttackPlan,
    AttackResult,
    Finding,
    JudgeResult,
    ScanConfiguration,
    ScanHistory,
    TargetProfile,
)
from sentinelllm.discovery.base import DiscoveryAgent
from sentinelllm.evaluation.evaluator import FinalEvaluator
from sentinelllm.history.store import HistoryStore
from sentinelllm.judging.judge import AttackJudge
from sentinelllm.planning.attack_planner import AttackPlanner
from sentinelllm.reporting.base import ReportGenerator
from sentinelllm.verification.verifier import VerificationComponent, VerificationResult


class MockTargetConnector(TargetConnector):
    async def send(self, request: dict[str, object]) -> TargetResponse:
        return TargetResponse(status_code=200, body="test response")


class MockDiscoveryAgent(DiscoveryAgent):
    async def discover(
        self, configuration: ScanConfiguration, connector: TargetConnector
    ) -> TargetProfile:
        return TargetProfile(target_url=configuration.target_url)


class MockAttackPlanner(AttackPlanner):
    async def plan(
        self, profile: TargetProfile, configuration: ScanConfiguration
    ) -> tuple[AttackPlan, ...]:
        return ()


class MockAttackAgent(AttackAgent):
    async def create_jobs(
        self, plans: tuple[AttackPlan, ...], configuration: ScanConfiguration
    ) -> tuple[AttackJob, ...]:
        return ()


class MockAttackExecutor(AttackExecutor):
    async def execute(self, job: AttackJob, connector: TargetConnector) -> AttackResult:
        return AttackResult(job_id=job.job_id, http_status=200, response="test response")


class MockAttackJudge(AttackJudge):
    async def judge(self, plan: AttackPlan, result: AttackResult) -> JudgeResult:
        return JudgeResult(outcome=JudgeOutcome.INCONCLUSIVE, confidence=0.0, reason="test mock")


class MockVerificationComponent(VerificationComponent):
    async def verify(self, finding: Finding) -> VerificationResult:
        return VerificationResult(
            finding_id=finding.finding_id,
            status=VerificationStatus.NOT_IMPLEMENTED,
            reason="test mock",
        )


class MockFinalEvaluator(FinalEvaluator):
    async def evaluate(
        self, plan: AttackPlan, result: AttackResult, judgment: JudgeResult
    ) -> tuple[Finding, ...]:
        return ()


class MockHistoryStore(HistoryStore):
    def __init__(self) -> None:
        self.started_configurations: list[ScanConfiguration] = []

    def start_scan(self, configuration: ScanConfiguration) -> ScanHistory:
        self.started_configurations.append(configuration)
        return ScanHistory(scan=configuration)

    def get_scan(self, scan_id: str) -> ScanHistory | None:
        return None


class MockReportGenerator(ReportGenerator):
    def generate(self, history: ScanHistory, output_directory: Path) -> Path:
        return output_directory / "mock-report.json"
