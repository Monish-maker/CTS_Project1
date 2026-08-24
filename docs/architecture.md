# SentinelLLM Architecture

## Scope

The implementation preserves the component flow in the repository architecture image. Network
communication belongs exclusively to `TargetConnector`; planning and the adaptive Agent do not
send requests. Every proposed job crosses `AttackPolicy` before execution.

## Data flow

```text
CLI -> ScanOrchestrator -> TargetConnector -> DiscoveryAgent -> TargetProfile
    -> AttackPlanner -> AttackPlan -> AttackAgent -> AttackJob -> AttackExecutor
    -> AttackResult -> Response Analysis -> AttackJudge -> Hypothesis Update
    -> Adaptation Decision -> next AttackJob / Verification -> Complete Scan History
    -> FinalEvaluator -> Security Report + Adaptive Attack Report
```

`ScanOrchestrator.start` intentionally remains a no-traffic pending-scan operation for dry runs.
`ScanOrchestrator.run` executes the complete bounded workflow. Every iteration is persisted as
structured jobs, results, observations, evidence, judgments, hypotheses, policy decisions, and
adaptation decisions before the next job is selected.

## Responsibilities and contracts

| Component        | Contract                | Responsibility                                                |
| ---------------- | ----------------------- | ------------------------------------------------------------- |
| Target connector | `TargetConnector`       | Async authorized target transport returning `TargetResponse`. |
| Discovery        | `DiscoveryAgent`        | Produces a `TargetProfile` from permitted target information. |
| Planning         | `AttackPlanner`         | Produces structured `AttackPlan` values.                      |
| Attack agent     | `AttackAgent`           | Selects response-driven strategies and creates `AttackJob`s.  |
| Execution        | `AttackExecutor`        | Executes a job and returns raw `AttackResult` evidence.       |
| Judging          | `AttackJudge`           | Produces a bounded `JudgeResult`.                             |
| Verification     | `VerificationComponent` | Confirms independently reproduced candidate findings.         |
| Evaluation       | `FinalEvaluator`        | Classifies corroborated evidence into `Finding` values.       |
| History          | `HistoryStore`          | Persists and retrieves `ScanHistory`.                         |
| Reporting        | `ReportGenerator`       | Projects history into four separate report artifacts.         |

Discovery uses structured parsers for same-origin OpenAPI documents and HTML forms. Parsed
`EndpointProfile` values carry URL, method, parameters, content types, and source. Planning
selects an allowed writable endpoint and records that choice in `AttackPlan`; generated jobs use
the selected method and parameter. Untrusted documents cannot introduce another origin.

`SQLiteHistoryStore` is the production CLI default for real scans and writes lossless tagged
JSON snapshots into SQLite after every lifecycle transition. `InMemoryHistoryStore` remains
available for dry runs and tests. Either can be replaced through the same contract.

## Dependency direction

The CLI is the composition root. It creates concrete adapters and injects them into
`ScanOrchestrator`. The orchestrator depends only on abstract component contracts; it
does not perform HTTP, attack planning, result judging, or report rendering itself.
Domain models in `core` do not depend on scanner components. This avoids circular imports
and lets each component be developed and tested independently.

## Logging and sensitive data

`core.logging.configure_logging` centralizes the logging setup. Scan initialization logs
the scan identifier only. The orchestrator emits event metadata for discovery, planning, policy,
execution, judging, adaptation, verification, final evaluation, report generation, and scan
completion. It never logs authorization headers, API keys, request bodies, or response bodies.

## Provider and policy separation

`LLMProvider` receives bounded observations and candidate strategy IDs. Its output must contain
the required fields and values from the caller-owned schema. Invalid output, timeout, rate-limit,
transport, and provider failures produce deterministic fallback metadata. Provider output cannot
bypass `AttackPolicy`, change scope, increase budgets, or communicate with the target.

Built-in HTTP adapters support generic/local JSON, OpenAI-compatible chat completions, Azure
OpenAI authentication, and Anthropic messages. The same provider contract can assist hypothesis
metadata, ambiguous-response interpretation, and strategy selection. Judge evidence references
always come from recorded `AttackResult` values, never provider output.

`HttpTargetConnector` owns HTTP/HTTPS communication, environment-derived authentication headers,
cookies, retries, timeout, concurrency, pacing, response normalization, and an actual request
ceiling. `AttackExecutor` never creates another network client.
Automatic redirects are disabled so an in-scope request cannot silently contact an out-of-scope
destination. Redirects are normalized as evidence and require a separately proposed,
policy-approved job before any destination is contacted.

## Extending SentinelLLM

### Add a strategy

Create an `AttackStrategy` with applicability, expected signals, success criteria, stop
conditions, and remediation, then register it in `StrategyRegistry`. The planner and Agent
consume the registry without changes.

### Add a connector

Implement `TargetConnector.send` asynchronously and inject it in place of
`HttpTargetConnector`. Discovery and execution remain unaware of transport details. Scope and
request authorization remain in the deterministic `AttackPolicy` gate.

### Add a judge

Implement `AttackJudge.judge` with deterministic, reviewable evidence rules before optional
LLM-assisted interpretation. Return an explicit `JudgeResult`; do not declare a finding
directly. The evaluator and verifier remain responsible for findings.

### Add an LLM provider

Provider integrations must return schema-validated strategy, hypothesis, observation, or
finding decisions and fall back to deterministic behavior on timeout, malformed output, rate
limits, provider failure, or context overflow. Providers never receive authority to send a
request, alter scope, or change budgets.

## Testing

`tests/unit/test_adaptive.py` uses an in-process target connector to prove that a no-signal
response causes a strategy switch, a subsequent controlled signal causes verification, and a
distinct reproduction job is required before a finding is emitted. It also covers all-category
strategy registration, applicability, duplicate prevention, scope enforcement, budgets, four
report artifacts, and cross-report finding IDs.

`tests/unit/test_discovery.py` verifies OpenAPI request-body extraction, HTML forms, malformed
documents, and same-origin filtering. `tests/unit/test_llm.py` verifies schema rejection,
provider fallback, hypothesis and Judge assistance, dedicated protocol envelopes, and adapter
selection.
`tests/unit/test_edge_cases.py` covers partial signals, abandonment, timeout/retry budgets,
cancellation persistence, and failed verification. `tests/integration/test_demo_target.py`
exercises OpenAPI-selected `/chat` execution, redirect protection, the real HTTP connector,
session behavior, adaptive loop, SQLite restoration, final evaluation, and all four report files
against `demo.target_app`. Every registered strategy is tested through generation, judging,
candidate evaluation, and remediation creation.

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
