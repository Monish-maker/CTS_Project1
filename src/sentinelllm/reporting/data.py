"""Structured projections for the two distinct report purposes."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, cast

from sentinelllm.core.enums import AttackCategory, CoverageStatus, JudgeOutcome, VerificationStatus
from sentinelllm.core.models import ScanHistory
from sentinelllm.planning.strategies import build_default_registry


def security_report_data(history: ScanHistory) -> dict[str, Any]:
    findings = [asdict(item) for item in history.findings]
    immediate_actions = tuple(
        dict.fromkeys(action for item in history.findings for action in item.immediate_actions)
    )
    recommended_actions = tuple(
        dict.fromkeys(action for item in history.findings for action in item.recommended_actions)
    )
    validation_steps = tuple(
        dict.fromkeys(action for item in history.findings for action in item.validation_steps)
    )
    severity = {name: 0 for name in ("critical", "high", "medium", "low", "informational")}
    for finding in history.findings:
        severity[finding.severity.value] += 1
    registry = build_default_registry()
    coverage = []
    for category in AttackCategory:
        category_plans = [item for item in history.plans if item.category == category]
        category_findings = [
            item
            for item in history.findings
            if item.attack_id in {plan.attack_id for plan in category_plans}
        ]
        tested = bool(
            category_plans
            and any(
                job.attack_id in {plan.attack_id for plan in category_plans} for job in history.jobs
            )
        )
        verified = [
            item
            for item in category_findings
            if item.verification_status == VerificationStatus.VERIFIED
        ]
        attack_ids = {plan.attack_id for plan in category_plans}
        job_ids = {job.job_id for job in history.jobs if job.attack_id in attack_ids}
        category_judgments = [item for item in history.judge_results if item.job_id in job_ids]
        inconclusive = bool(category_judgments) and all(
            item.outcome in {JudgeOutcome.ERROR, JudgeOutcome.INCONCLUSIVE}
            for item in category_judgments
        )
        applicable = (
            bool(registry.applicable(category, history.target_profile))
            if history.target_profile
            else True
        )
        status = (
            CoverageStatus.VULNERABLE
            if verified
            else CoverageStatus.NOT_APPLICABLE
            if not applicable
            else CoverageStatus.INCONCLUSIVE
            if inconclusive
            else CoverageStatus.NO_FINDING
            if tested
            else CoverageStatus.NOT_TESTED
        )
        coverage.append(
            {
                "category": category.value,
                "status": status.value,
                "strategies_available": len(registry.for_category(category)),
                "strategies_evaluated": len(
                    {
                        job.metadata.get("strategy_id")
                        for job in history.jobs
                        if job.attack_id in {plan.attack_id for plan in category_plans}
                    }
                ),
                "findings": [item.finding_id for item in category_findings],
                "verified_findings": [item.finding_id for item in verified],
                "severity": max((item.severity.value for item in verified), default=None),
                "confidence": max((item.confidence for item in category_findings), default=0.0),
            }
        )
    return cast(
        dict[str, Any],
        _safe(
            {
                "report_type": "security_vulnerability_assessment",
                "scan": _scan(history),
                "target": asdict(history.target_profile)
                if history.target_profile
                else {"target_url": history.scan.target_url},
                "executive_summary": {
                    "overall_assessment": "Vulnerabilities verified"
                    if history.findings
                    else "No verified vulnerabilities; review coverage status",
                    "total_vulnerabilities": len(history.findings),
                    "severity_distribution": severity,
                    "overall_confidence": max(
                        (item.confidence for item in history.findings), default=0.0
                    ),
                },
                "owasp_coverage": coverage,
                "findings": findings,
                "remediation_summary": {
                    "immediate_actions": immediate_actions,
                    "recommended_actions": recommended_actions,
                    "validation_steps": validation_steps,
                },
                "evidence": [asdict(item) for item in history.evidence],
            }
        ),
    )


def attack_report_data(history: ScanHistory) -> dict[str, Any]:
    results = {item.job_id: item for item in history.results}
    observations = {item.job_id: item for item in history.observations}
    judgments = {item.job_id: item for item in history.judge_results}
    adaptations = {item.triggering_job_id: item for item in history.adaptations}
    jobs = {item.job_id: item for item in history.jobs}
    iterations = []
    for job in history.jobs:
        adaptation = adaptations.get(job.job_id)
        next_job = next(
            (
                candidate
                for candidate in history.jobs
                if adaptation and candidate.job_id == adaptation.next_job_id
            ),
            None,
        )
        iterations.append(
            {
                "iteration": job.iteration,
                "category": job.metadata.get("category"),
                "strategy": job.metadata.get("strategy"),
                "hypothesis": job.metadata.get("hypothesis_id"),
                "attack_job": asdict(job),
                "target_response": asdict(results[job.job_id]) if job.job_id in results else None,
                "response_analysis": asdict(observations[job.job_id])
                if job.job_id in observations
                else None,
                "judge_result": asdict(judgments[job.job_id]) if job.job_id in judgments else None,
                "adaptation_decision": asdict(adaptations[job.job_id])
                if job.job_id in adaptations
                else None,
                "next_attack_job": asdict(next_job) if next_job else None,
            }
        )
    strategy_statistics: dict[str, dict[str, dict[str, int]]] = {}
    for judgment in history.judge_results:
        statistic_job = jobs.get(judgment.job_id)
        if not statistic_job:
            continue
        category = str(statistic_job.metadata.get("category", "unknown"))
        strategy = str(statistic_job.metadata.get("strategy_id", "unknown"))
        counters = strategy_statistics.setdefault(category, {}).setdefault(
            strategy,
            {
                "attempted": 0,
                "successful": 0,
                "unsuccessful": 0,
                "follow_up": 0,
                "verification": 0,
            },
        )
        counters["attempted"] += 1
        if judgment.outcome in {JudgeOutcome.SUCCESSFUL, JudgeOutcome.POTENTIAL_SUCCESS}:
            counters["successful"] += 1
        else:
            counters["unsuccessful"] += 1
        adaptation = adaptations.get(judgment.job_id)
        if adaptation and adaptation.next_job_id:
            counters["follow_up"] += 1
        if adaptation and adaptation.decision.value == "verify":
            counters["verification"] += 1

    return cast(
        dict[str, Any],
        _safe(
            {
                "report_type": "adaptive_attack_journey",
                "scan": _scan(history),
                "attack_session": {
                    "scan_id": history.scan.scan_id,
                    "target": history.scan.target_url,
                },
                "iterations": iterations,
                "attack_jobs": [asdict(item) for item in history.jobs],
                "responses": [asdict(item) for item in history.results],
                "observations": [asdict(item) for item in history.observations],
                "judge_results": [asdict(item) for item in history.judge_results],
                "hypotheses": [asdict(item) for item in history.hypotheses],
                "adaptations": [asdict(item) for item in history.adaptations],
                "strategy_transitions": [
                    asdict(item)
                    for item in history.adaptations
                    if item.next_strategy_id and item.next_strategy_id != item.previous_strategy_id
                ],
                "strategy_statistics": strategy_statistics,
                "verification_events": list(history.verification_results),
                "candidate_findings": [asdict(item) for item in history.candidate_findings],
                "attack_statistics": {
                    "total_attacks": len(history.results),
                    "attack_requests": sum(
                        int(item.response_metadata.get("attempt", 0)) + 1
                        for item in history.results
                    ),
                    "total_requests": sum(
                        int(item.response_metadata.get("attempt", 0)) + 1
                        for item in history.results
                    )
                    + int(
                        history.target_profile.discovery_metadata.get("request_count", 0)
                        if history.target_profile
                        else 0
                    ),
                    "discovery_requests": int(
                        history.target_profile.discovery_metadata.get("request_count", 0)
                        if history.target_profile
                        else 0
                    ),
                    "total_jobs": len(history.jobs),
                    "total_adaptive_iterations": len(history.adaptations),
                    "strategy_changes": sum(
                        item.next_strategy_id not in {None, item.previous_strategy_id}
                        for item in history.adaptations
                    ),
                    "hypothesis_updates": len(history.adaptations),
                    "follow_up_attacks": sum(
                        item.next_job_id is not None for item in history.adaptations
                    ),
                    "attacks_triggered_by_previous_results": sum(
                        item.next_job_id is not None for item in history.adaptations
                    ),
                    "duplicate_jobs_prevented": history.duplicate_jobs_prevented,
                    "rejected_jobs": history.rejected_jobs,
                    "verification_transitions": sum(
                        item.decision.value == "verify" for item in history.adaptations
                    ),
                    "attacks_stopped_sufficient_evidence": sum(
                        item.decision.value == "stop"
                        and item.confidence >= 0.7
                        and bool(item.evidence_references)
                        for item in history.adaptations
                    ),
                    "abandoned_hypotheses": sum(
                        item.status.value == "abandoned" for item in history.hypotheses
                    ),
                    "execution_time_seconds": round(
                        sum(item.execution_duration_seconds or 0.0 for item in history.results),
                        6,
                    ),
                    "retries": sum(
                        int(item.response_metadata.get("attempt", 0)) for item in history.results
                    ),
                },
                "finding_links": [
                    {
                        "finding_id": item.finding_id,
                        "job_ids": item.job_ids,
                        "strategy_ids": item.strategy_ids,
                        "verification_ids": item.verification_ids,
                    }
                    for item in history.findings
                ],
            }
        ),
    )


def _scan(history: ScanHistory) -> dict[str, Any]:
    return {
        "scan_id": history.scan.scan_id,
        "status": history.status.value,
        "started_at": history.started_at,
        "finished_at": history.finished_at,
        "errors": history.errors,
    }


_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set_cookie",
    "api_key",
    "apikey",
    "password",
    "secret",
    "token",
}


def _safe(value: Any, key: str = "") -> Any:
    """Recursively redact credentials and bound report string sizes."""
    normalized = key.lower().replace("-", "_")
    if any(sensitive in normalized for sensitive in _SENSITIVE_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(item_key): _safe(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    if isinstance(value, str) and len(value) > 8000:
        return value[:8000] + "...[truncated]"
    return value
