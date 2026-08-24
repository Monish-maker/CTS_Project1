"""Attack execution boundary."""

from abc import ABC, abstractmethod
from time import monotonic

from sentinelllm.connector.base import TargetConnector
from sentinelllm.core.models import AttackJob, AttackResult


class AttackExecutor(ABC):
    """Executes an approved attack job through the target connector."""

    @abstractmethod
    async def execute(self, job: AttackJob, connector: TargetConnector) -> AttackResult:
        """Return raw execution evidence without judging it."""
        raise NotImplementedError


class DefaultAttackExecutor(AttackExecutor):
    """Execute only through the injected connector and normalize failures."""

    async def execute(self, job: AttackJob, connector: TargetConnector) -> AttackResult:
        """Execute one policy-approved job without interpreting the response."""
        started = monotonic()
        try:
            response = await connector.send(job.request)
            error = response.metadata.get("error")
            return AttackResult(
                job_id=job.job_id,
                http_status=response.status_code,
                response=response.body,
                response_metadata={
                    **response.metadata,
                    "headers": response.headers,
                    "strategy_id": job.metadata.get("strategy_id"),
                    "expected_signals": job.metadata.get("expected_signals", ()),
                },
                execution_duration_seconds=monotonic() - started,
                errors=(str(error),) if error else (),
            )
        except Exception as error:  # Connector failures become auditable results.
            return AttackResult(
                job_id=job.job_id,
                http_status=None,
                response=None,
                execution_duration_seconds=monotonic() - started,
                errors=(f"{type(error).__name__}: {error}",),
            )
