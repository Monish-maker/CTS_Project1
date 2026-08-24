"""Final finding evaluator."""

from abc import ABC, abstractmethod
from dataclasses import replace
from uuid import uuid4

from sentinelllm.core.enums import JudgeOutcome, VerificationStatus
from sentinelllm.core.models import AttackPlan, AttackResult, Finding, JudgeResult, ScanHistory
from sentinelllm.evaluation.remediation import remediation_for


class FinalEvaluator(ABC):
    """Classifies corroborated judged results into security findings."""

    @abstractmethod
    async def evaluate(
        self,
        plan: AttackPlan,
        result: AttackResult,
        judgment: JudgeResult,
    ) -> tuple[Finding, ...]:
        """Create findings only from implemented evaluation rules."""
        raise NotImplementedError

    async def evaluate_history(self, history: ScanHistory) -> tuple[Finding, ...]:
        """Classify final findings from complete history after verification."""
        return history.findings


class DefaultFinalEvaluator(FinalEvaluator):
    """Convert only strong, traceable judgments into candidate findings."""

    async def evaluate(
        self,
        plan: AttackPlan,
        result: AttackResult,
        judgment: JudgeResult,
    ) -> tuple[Finding, ...]:
        """Create a pending finding; verification remains a separate required step."""
        if judgment.outcome not in {JudgeOutcome.SUCCESSFUL, JudgeOutcome.POTENTIAL_SUCCESS}:
            return ()
        guidance = remediation_for(plan.category)
        return (
            Finding(
                finding_id=f"F-{uuid4().hex[:12]}",
                title=f"Potential {plan.category.value.replace('_', ' ').title()}",
                description=judgment.reason,
                severity=plan.risk_level,
                confidence=judgment.confidence,
                owasp_category=plan.owasp_mapping,
                attack_id=plan.attack_id,
                evidence=judgment.evidence_references or result.evidence,
                impact=f"The target may be affected by {plan.category.value.replace('_', ' ')}.",
                remediation=plan.remediation_guidance,
                missing_security_control=guidance.missing_control,
                immediate_actions=guidance.immediate_actions,
                recommended_actions=guidance.recommended_actions,
                validation_steps=guidance.validation_steps,
                verification_status=VerificationStatus.PENDING,
                affected_target=str(result.response_metadata.get("url", "")),
                affected_endpoint=str(result.response_metadata.get("url", "")),
                affected_component=plan.strategy,
                reproduction_summary=(
                    "Repeat the linked controlled strategy and compare against baseline."
                ),
                job_ids=(result.job_id,),
                result_ids=(result.result_id,),
                strategy_ids=(str(result.response_metadata.get("strategy_id", plan.strategy_id)),),
            ),
        )

    async def evaluate_history(self, history: ScanHistory) -> tuple[Finding, ...]:
        """Promote only verified candidates and deduplicate correlated findings."""
        verification_by_finding = {
            str(item.get("finding_id")): item for item in history.verification_results
        }
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for candidate in history.candidate_findings:
            verification = verification_by_finding.get(candidate.finding_id)
            if not verification or verification.get("status") != VerificationStatus.VERIFIED:
                continue
            key = (candidate.owasp_category, candidate.attack_id)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                replace(
                    candidate,
                    verification_status=VerificationStatus.VERIFIED,
                    verification_ids=(str(verification.get("verification_id", "")),),
                )
            )
        return tuple(findings)
