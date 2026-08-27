"""Central composition root for the future scanner workflow."""

import asyncio
import logging
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

from sentinelllm.attacks.agent import AttackAgent
from sentinelllm.attacks.analysis import analyze_response
from sentinelllm.attacks.executor import AttackExecutor
from sentinelllm.attacks.policy import AttackPolicy
from sentinelllm.connector.base import TargetConnector
from sentinelllm.core.enums import JobStatus, ScanStatus
from sentinelllm.core.models import AttackResult, Finding, ScanConfiguration, ScanHistory
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
        """Record a pending scan without causing target traffic."""
        self._logger.info("scan initialized scan_id=%s", configuration.scan_id)
        return self._history.start_scan(configuration)

    async def run(self, configuration: ScanConfiguration) -> ScanHistory:
        """Execute the bounded response-driven scan and generate all report artifacts."""
        history = replace(self.start(configuration), status=ScanStatus.RUNNING)
        history = self._history.save_scan(history)
        deadline = monotonic() + configuration.maximum_scan_duration_seconds
        try:
            self._logger.info("event=discovery_started scan_id=%s", configuration.scan_id)
            profile = await asyncio.wait_for(
                self._discovery.discover(configuration, self._connector),
                timeout=max(deadline - monotonic(), 0.001),
            )
            self._logger.info(
                "event=discovery_completed scan_id=%s endpoints=%d capabilities=%d",
                configuration.scan_id,
                len(profile.identified_endpoints),
                len(profile.capabilities),
            )
            plans = await self._planner.plan(profile, configuration)
            self._logger.info(
                "event=plan_created scan_id=%s plans=%d",
                configuration.scan_id,
                len(plans),
            )
            history = self._save(replace(history, target_profile=profile, plans=plans))
            policy = AttackPolicy(configuration)
            initial_jobs = await self._attack_agent.create_jobs(plans, configuration)
            plan_by_id = {plan.attack_id: plan for plan in plans}
            baseline = AttackResult(
                "discovery-baseline",
                profile.discovery_metadata.get("baseline_status"),
                str(profile.discovery_metadata.get("baseline_body", "")),
            )

            for initial_job in initial_jobs:
                plan = plan_by_id[initial_job.attack_id]
                hypothesis = self._attack_agent.create_hypothesis(plan)  # type: ignore[attr-defined]
                hypothesis = await self._attack_agent.refine_hypothesis(  # type: ignore[attr-defined]
                    plan, hypothesis
                )
                current_job = replace(
                    initial_job,
                    metadata={**initial_job.metadata, "hypothesis_id": hypothesis.hypothesis_id},
                )
                attempted: set[str] = set()
                history = self._save(replace(history, hypotheses=(*history.hypotheses, hypothesis)))
                candidate: Finding | None = None

                while current_job is not None:
                    if monotonic() >= deadline:
                        history = self._save(
                            replace(
                                history, errors=(*history.errors, "maximum scan duration exhausted")
                            )
                        )
                        break
                    policy_decision = policy.validate(current_job)
                    self._logger.info(
                        "event=job_policy_decision scan_id=%s job_id=%s approved=%s",
                        configuration.scan_id,
                        current_job.job_id,
                        policy_decision.approved,
                    )
                    history = self._save(
                        replace(
                            history,
                            jobs=(*history.jobs, current_job),
                            policy_decisions=(*history.policy_decisions, policy_decision),
                        )
                    )
                    if not policy_decision.approved:
                        self._logger.warning(
                            "event=job_rejected scan_id=%s job_id=%s reason=%s",
                            configuration.scan_id,
                            current_job.job_id,
                            policy_decision.reason,
                        )
                        rejected = replace(current_job, status=JobStatus.REJECTED)
                        history = self._save(
                            replace(
                                history,
                                jobs=(*history.jobs[:-1], rejected),
                                rejected_jobs=history.rejected_jobs + 1,
                                duplicate_jobs_prevented=history.duplicate_jobs_prevented
                                + ("duplicate" in policy_decision.reason),
                            )
                        )
                        break

                    running_job = replace(current_job, status=JobStatus.RUNNING)
                    history = self._save(replace(history, jobs=(*history.jobs[:-1], running_job)))
                    attempted.add(str(current_job.metadata.get("strategy_id", "")))
                    result = await asyncio.wait_for(
                        self._executor.execute(current_job, self._connector),
                        timeout=max(deadline - monotonic(), 0.001),
                    )
                    finished_job = replace(
                        current_job,
                        status=JobStatus.FAILED if result.errors else JobStatus.COMPLETED,
                    )
                    history = self._save(replace(history, jobs=(*history.jobs[:-1], finished_job)))
                    self._logger.info(
                        "event=job_executed scan_id=%s job_id=%s status=%s errors=%d",
                        configuration.scan_id,
                        current_job.job_id,
                        result.http_status,
                        len(result.errors),
                    )
                    if result.http_status and result.http_status >= 400:
                        self._logger.warning(
                            "event=target_error_response scan_id=%s job_id=%s status=%s body=%r",
                            configuration.scan_id,
                            current_job.job_id,
                            result.http_status,
                            (result.response or "")[:500],
                        )
                    observation, evidence = analyze_response(current_job, result, baseline)
                    result = replace(
                        result,
                        evidence=observation.evidence_references,
                        request_fingerprint=policy_decision.fingerprint,
                    )
                    judgment = await self._judge.judge(plan, result, observation)
                    self._logger.info(
                        "event=judge_completed scan_id=%s job_id=%s outcome=%s confidence=%.2f",
                        configuration.scan_id,
                        current_job.job_id,
                        judgment.outcome.value,
                        judgment.confidence,
                    )
                    generated = await self._evaluator.evaluate(plan, result, judgment)
                    if generated:
                        new_candidate = generated[0]
                        candidate = (
                            replace(
                                candidate,
                                confidence=max(candidate.confidence, new_candidate.confidence),
                                evidence=tuple(
                                    dict.fromkeys((*candidate.evidence, *new_candidate.evidence))
                                ),
                                job_ids=tuple(
                                    dict.fromkeys((*candidate.job_ids, *new_candidate.job_ids))
                                ),
                                result_ids=tuple(
                                    dict.fromkeys(
                                        (*candidate.result_ids, *new_candidate.result_ids)
                                    )
                                ),
                                strategy_ids=tuple(
                                    dict.fromkeys(
                                        (*candidate.strategy_ids, *new_candidate.strategy_ids)
                                    )
                                ),
                            )
                            if candidate
                            else new_candidate
                        )
                    history = self._save(
                        replace(
                            history,
                            results=(*history.results, result),
                            evidence=(*history.evidence, *evidence),
                            observations=(*history.observations, observation),
                            judge_results=(*history.judge_results, judgment),
                        )
                    )
                    decision, hypothesis, next_job = await self._attack_agent.adapt(  # type: ignore[attr-defined]
                        plan,
                        configuration,
                        profile,
                        hypothesis,
                        observation,
                        judgment,
                        attempted,
                        current_job.iteration,
                    )
                    self._logger.info(
                        "event=adaptation_decided scan_id=%s job_id=%s "
                        "decision=%s next_strategy=%s",
                        configuration.scan_id,
                        current_job.job_id,
                        decision.decision.value,
                        decision.next_strategy_id or "none",
                    )
                    if next_job is not None:
                        next_job = replace(
                            next_job,
                            metadata={
                                **next_job.metadata,
                                "hypothesis_id": hypothesis.hypothesis_id,
                            },
                        )
                        decision = replace(decision, next_job_id=next_job.job_id)
                    hypotheses = tuple(
                        item
                        for item in history.hypotheses
                        if item.hypothesis_id != hypothesis.hypothesis_id
                    ) + (hypothesis,)
                    history = self._save(
                        replace(
                            history,
                            hypotheses=hypotheses,
                            adaptations=(*history.adaptations, decision),
                        )
                    )
                    current_job = next_job

                if candidate is not None:
                    self._logger.info(
                        "event=verification_started scan_id=%s finding_id=%s",
                        configuration.scan_id,
                        candidate.finding_id,
                    )
                    history = self._save(
                        replace(
                            history,
                            candidate_findings=(*history.candidate_findings, candidate),
                        )
                    )
                    verification = await self._verifier.verify(candidate)
                    self._logger.info(
                        "event=verification_completed scan_id=%s finding_id=%s category=%s "
                        "status=%s reason=%s jobs=%d strategies=%d",
                        configuration.scan_id,
                        candidate.finding_id,
                        candidate.owasp_category,
                        verification.status.value,
                        verification.reason,
                        len(set(candidate.job_ids)),
                        len(set(candidate.strategy_ids)),
                    )
                    history = self._save(
                        replace(
                            history,
                            verification_results=(
                                *history.verification_results,
                                asdict(verification),
                            ),
                        )
                    )

            findings = await self._evaluator.evaluate_history(history)
            self._logger.info(
                "event=final_evaluation_completed scan_id=%s findings=%d",
                configuration.scan_id,
                len(findings),
            )
            history = self._save(
                replace(
                    history,
                    findings=findings,
                    status=ScanStatus.COMPLETED,
                    finished_at=datetime.now(UTC),
                )
            )
        except asyncio.CancelledError:
            history = self._save(
                replace(
                    history,
                    status=ScanStatus.CANCELLED,
                    errors=(*history.errors, "scan cancelled by caller"),
                    finished_at=datetime.now(UTC),
                )
            )
            output = Path(configuration.reporting_output_directory) / configuration.scan_id
            self._reporter.generate(history, output)
            self._logger.warning(
                "event=scan_cancelled scan_id=%s output=%s",
                configuration.scan_id,
                output,
            )
            raise
        except Exception as error:
            self._logger.exception("scan failed scan_id=%s", configuration.scan_id)
            history = self._save(
                replace(
                    history,
                    status=ScanStatus.FAILED,
                    errors=(*history.errors, f"{type(error).__name__}: {error}"),
                    finished_at=datetime.now(UTC),
                )
            )

        output = Path(configuration.reporting_output_directory) / configuration.scan_id
        self._reporter.generate(history, output)
        self._logger.info(
            "event=reports_generated scan_id=%s output=%s",
            configuration.scan_id,
            output,
        )
        self._logger.info(
            "event=scan_completed scan_id=%s status=%s",
            configuration.scan_id,
            history.status.value,
        )
        return history

    def _save(self, history: ScanHistory) -> ScanHistory:
        return self._history.save_scan(history)
