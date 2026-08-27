"""Deterministic tests for strategies, policy, and adaptive orchestration."""

import asyncio
import json
from pathlib import Path
from typing import Any, cast

from sentinelllm.attacks.agent import DefaultAttackAgent
from sentinelllm.attacks.executor import DefaultAttackExecutor
from sentinelllm.attacks.policy import AttackPolicy
from sentinelllm.connector.base import TargetConnector, TargetResponse
from sentinelllm.core.enums import (
    AdaptiveDecisionType,
    AttackCategory,
    JobStatus,
    JudgeOutcome,
    RiskLevel,
    ScanStatus,
)
from sentinelllm.core.models import (
    AttackJob,
    AttackPlan,
    AttackResult,
    ScanConfiguration,
    TargetProfile,
)
from sentinelllm.discovery.discovery_agent import DefaultDiscoveryAgent
from sentinelllm.evaluation.evaluator import DefaultFinalEvaluator
from sentinelllm.history.store import InMemoryHistoryStore, SQLiteHistoryStore
from sentinelllm.judging.judge import DefaultAttackJudge
from sentinelllm.orchestrator.scan_orchestrator import ScanOrchestrator
from sentinelllm.planning.attack_planner import DefaultAttackPlanner
from sentinelllm.planning.strategies import build_default_registry
from sentinelllm.reporting.bundle import ReportBundleGenerator
from sentinelllm.verification.verifier import DefaultVerificationComponent


class AdaptiveTargetConnector(TargetConnector):
    """Return behavior determined by the actual incoming attack payload."""

    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []
        self.attack_count = 0

    async def send(self, request: dict[str, object]) -> TargetResponse:
        self.requests.append(request)
        if request.get("method") == "GET":
            return TargetResponse(
                200, '{"service":"chat model"}', {"Content-Type": "application/json"}
            )
        self.attack_count += 1
        payload = cast(dict[str, Any], request.get("json", {}))
        prompt = str(payload.get("prompt", ""))
        body = "No useful signal" if self.attack_count == 1 else prompt
        return TargetResponse(200, body, {"Content-Type": "text/plain"})


def test_registry_contains_five_strategies_for_every_owasp_2026_category() -> None:
    registry = build_default_registry()

    assert len(registry.all()) == 50
    assert all(len(registry.for_category(category)) == 5 for category in AttackCategory)
    profile = TargetProfile(target_url="https://example.test", has_rag=False)
    assert registry.applicable(AttackCategory.VECTOR_AND_EMBEDDING_WEAKNESSES, profile) == ()


def test_every_strategy_generates_an_independent_job() -> None:
    registry = build_default_registry()
    agent = DefaultAttackAgent(registry=registry)
    configuration = ScanConfiguration(target_url="https://example.test")

    for index, strategy in enumerate(registry.all()):
        plan = AttackPlan(
            attack_id=f"AT-{index}",
            category=strategy.category,
            owasp_mapping="OWASP:2026",
            objective=strategy.objective,
            preconditions=(),
            strategy=strategy.name,
            expected_indicators=strategy.expected_signals,
            risk_level=RiskLevel.MEDIUM,
            strategy_id=strategy.strategy_id,
        )
        job = asyncio.run(agent.create_jobs((plan,), configuration))[0]

        assert job.metadata["strategy_id"] == strategy.strategy_id
        assert job.metadata["expected_signals"] == strategy.expected_signals
        assert strategy.prompt_template == job.request["json"]["prompt"]


def test_anthropic_target_jobs_use_messages_payload() -> None:
    registry = build_default_registry()
    strategy = registry.for_category(AttackCategory.PROMPT_INJECTION)[0]
    agent = DefaultAttackAgent(registry=registry)
    configuration = scan_configuration_from_mapping(
        {
            "target": {
                "url": "https://api.anthropic.com/v1/messages",
                "request": {
                    "format": "anthropic_messages",
                    "model": "claude-3-5-sonnet-latest",
                    "max_tokens": 256,
                },
            }
        }
    )
    plan = AttackPlan(
        attack_id="AT-anthropic",
        category=strategy.category,
        owasp_mapping="OWASP:2026",
        objective=strategy.objective,
        preconditions=(),
        strategy=strategy.name,
        expected_indicators=strategy.expected_signals,
        risk_level=RiskLevel.MEDIUM,
        strategy_id=strategy.strategy_id,
    )

    job = asyncio.run(agent.create_jobs((plan,), configuration))[0]

    assert job.request["json"] == {
        "model": "claude-3-5-sonnet-latest",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": strategy.prompt_template}],
    }


def test_every_strategy_has_successful_judge_and_candidate_finding_handling() -> None:
    registry = build_default_registry()
    judge = DefaultAttackJudge()
    evaluator = DefaultFinalEvaluator()

    for index, strategy in enumerate(registry.all()):
        plan = AttackPlan(
            attack_id=f"AT-result-{index}",
            category=strategy.category,
            owasp_mapping="OWASP:2026",
            objective=strategy.objective,
            preconditions=(),
            strategy=strategy.name,
            expected_indicators=strategy.expected_signals,
            risk_level=strategy.risk_level,
            strategy_id=strategy.strategy_id,
            remediation_guidance=strategy.remediation_guidance,
        )
        result = AttackResult(
            job_id=f"AJ-result-{index}",
            http_status=200,
            response=strategy.expected_signals[-1],
            response_metadata={"expected_signals": strategy.expected_signals},
            evidence=(f"EV-{index}",),
        )

        judgment = asyncio.run(judge.judge(plan, result))
        findings = asyncio.run(evaluator.evaluate(plan, result, judgment))

        assert judgment.outcome is JudgeOutcome.POTENTIAL_SUCCESS
        assert judgment.matched_criteria
        assert len(findings) == 1
        assert findings[0].owasp_category == "OWASP:2026"
        assert findings[0].recommended_actions


def test_policy_rejects_duplicate_out_of_scope_and_exhausted_budget() -> None:
    configuration = ScanConfiguration(
        target_url="https://example.test/api", maximum_requests=1, maximum_jobs=2
    )
    policy = AttackPolicy(configuration)
    job = AttackJob(
        "AJ-1",
        configuration.scan_id,
        "AT-1",
        1,
        request={"method": "POST", "url": "https://example.test/api", "json": {"prompt": "a"}},
        metadata={"strategy_id": "one"},
    )

    assert policy.validate(job).approved is True
    assert policy.validate(job).reason == "scan request budget exhausted"
    outside = AttackPolicy(configuration).validate(
        AttackJob("AJ-2", configuration.scan_id, "AT-1", 1, request={"url": "https://outside.test"})
    )
    assert outside.approved is False
    assert "outside" in outside.reason

    duplicate_policy = AttackPolicy(
        ScanConfiguration(target_url="https://example.test", maximum_requests=2)
    )
    assert duplicate_policy.validate(job).approved is True
    assert duplicate_policy.validate(job).reason == "duplicate attack fingerprint"


def test_target_response_drives_follow_up_and_generates_linked_reports(tmp_path: Path) -> None:
    connector = AdaptiveTargetConnector()
    history_store = InMemoryHistoryStore()
    orchestrator = ScanOrchestrator(
        connector=connector,
        discovery=DefaultDiscoveryAgent(),
        planner=DefaultAttackPlanner(),
        attack_agent=DefaultAttackAgent(),
        executor=DefaultAttackExecutor(),
        judge=DefaultAttackJudge(),
        verifier=DefaultVerificationComponent(),
        evaluator=DefaultFinalEvaluator(),
        history=history_store,
        reporter=ReportBundleGenerator(),
    )
    configuration = ScanConfiguration(
        target_url="https://example.test/api",
        enabled_attack_categories=(AttackCategory.PROMPT_INJECTION,),
        maximum_attack_iterations=3,
        maximum_requests=4,
        maximum_jobs=4,
        dry_run=False,
        reporting_output_directory=str(tmp_path),
    )

    history = asyncio.run(orchestrator.run(configuration))

    assert history.status is ScanStatus.COMPLETED
    assert len(history.results) == 3
    assert all(job.status is JobStatus.COMPLETED for job in history.jobs)
    assert history.jobs[0].request != history.jobs[1].request
    assert history.adaptations[0].decision is AdaptiveDecisionType.SWITCH_STRATEGY
    assert history.adaptations[1].decision is AdaptiveDecisionType.VERIFY
    assert history.adaptations[0].next_job_id == history.jobs[1].job_id
    assert history.candidate_findings
    assert history.findings
    assert len(history.findings[0].job_ids) == 2

    report_directory = tmp_path / configuration.scan_id
    expected = {
        "sentinelllm_security_report.html",
        "sentinelllm_security_report.json",
        "sentinelllm_attack_report.html",
        "sentinelllm_attack_report.json",
    }
    assert expected == {item.name for item in report_directory.iterdir()}
    security = json.loads((report_directory / "sentinelllm_security_report.json").read_text())
    attack = json.loads((report_directory / "sentinelllm_attack_report.json").read_text())
    finding_id = history.findings[0].finding_id
    assert security["findings"][0]["finding_id"] == finding_id
    assert security["findings"][0]["missing_security_control"]
    assert len(security["findings"][0]["recommended_actions"]) >= 3
    assert security["remediation_summary"]["immediate_actions"]
    assert attack["finding_links"][0]["finding_id"] == finding_id
    assert attack["strategy_statistics"]["prompt_injection"]
    assert attack["attack_statistics"]["attack_requests"] == 3
    assert attack["attack_statistics"]["discovery_requests"] == 3
    assert attack["attack_statistics"]["total_requests"] == 6
    assert "execution_time_seconds" in attack["attack_statistics"]
    security_html = (report_directory / "sentinelllm_security_report.html").read_text()
    assert "Recommended Corrective Measures" in security_html
    assert "How to Validate the Fix" in security_html
    attack_html = (report_directory / "sentinelllm_attack_report.html").read_text()
    assert "timeline-search" in attack_html
    assert "category-filter" in attack_html
    assert "filterTimeline" in attack_html


def test_sqlite_history_survives_store_recreation(tmp_path: Path) -> None:
    database = tmp_path / "history.sqlite3"
    configuration = ScanConfiguration(target_url="https://example.test", scan_id="durable")
    first = SQLiteHistoryStore(database)
    expected = first.start_scan(configuration)

    restored = SQLiteHistoryStore(database).get_scan("durable")

    assert restored == expected
