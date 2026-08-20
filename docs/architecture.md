# SentinelLLM Architecture: Phase 1

## Scope

Phase 1 establishes contracts and composition only. It does not communicate with targets,
discover capabilities, generate payloads, execute attacks, judge security outcomes, verify
findings, or create reports. Default production components raise
`FeatureNotImplementedError` whenever that unimplemented behavior is invoked.

## Data flow

```text
CLI -> ScanOrchestrator -> TargetConnector -> DiscoveryAgent -> TargetProfile
    -> AttackPlanner -> AttackPlan -> AttackAgent -> AttackJob -> AttackExecutor
    -> AttackResult -> AttackJudge -> VerificationComponent / FinalEvaluator
    -> HistoryStore -> ReportGenerator
```

In Phase 1 the orchestrator stops after it asks `HistoryStore` to create a `PENDING`
`ScanHistory`. This verifies dependency composition without causing target traffic.

## Responsibilities and contracts

| Component        | Contract                | Responsibility                                                |
| ---------------- | ----------------------- | ------------------------------------------------------------- |
| Target connector | `TargetConnector`       | Async authorized target transport returning `TargetResponse`. |
| Discovery        | `DiscoveryAgent`        | Produces a `TargetProfile` from permitted target information. |
| Planning         | `AttackPlanner`         | Produces structured `AttackPlan` values.                      |
| Attack agent     | `AttackAgent`           | Converts approved plans to `AttackJob` values.                |
| Execution        | `AttackExecutor`        | Executes a job and returns raw `AttackResult` evidence.       |
| Judging          | `AttackJudge`           | Produces a bounded `JudgeResult`.                             |
| Verification     | `VerificationComponent` | Re-tests a potential `Finding`.                               |
| Evaluation       | `FinalEvaluator`        | Classifies corroborated evidence into `Finding` values.       |
| History          | `HistoryStore`          | Persists and retrieves `ScanHistory`.                         |
| Reporting        | `ReportGenerator`       | Renders scan history into an output file.                     |

`InMemoryHistoryStore` is the only executable implementation because it has no security
side effects. It is explicitly non-durable and can later be replaced by SQLite or
PostgreSQL without changing orchestration code.

## Dependency direction

The CLI is the composition root. It creates concrete adapters and injects them into
`ScanOrchestrator`. The orchestrator depends only on abstract component contracts; it
does not perform HTTP, attack planning, result judging, or report rendering itself.
Domain models in `core` do not depend on scanner components. This avoids circular imports
and lets each component be developed and tested independently.

## Logging and sensitive data

`core.logging.configure_logging` centralizes the logging setup. Scan initialization logs
the scan identifier only. Implementations must add contextual fields such as `job_id`,
`attack_id`, `iteration`, and component name while never logging authorization headers,
API keys, or request/response secrets.

## Extending SentinelLLM

### Add an attack

Add an OWASP-aligned category or strategy definition under `planning`, implement an
`AttackPlanner` that yields `AttackPlan` values, and an `AttackAgent` that creates
controlled `AttackJob` values. Keep transport in `AttackExecutor` through the injected
connector. Register the implementations only in the CLI composition root.

### Add a connector

Implement `TargetConnector.send` asynchronously, enforce target authorization and
transport safety policy there, and inject it in place of `HttpTargetConnector`. Discovery
and execution should remain unaware of HTTP client details.

### Add a judge

Implement `AttackJudge.judge` with deterministic, reviewable evidence rules before any
LLM-assisted logic. Return an explicit `JudgeResult`; do not declare a finding directly.
The evaluator remains responsible for converting corroborated conclusions into findings.

## Development commands

Python 3.11+ is required.

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
mypy .
sentinelllm --help
sentinelllm scan --help
```
