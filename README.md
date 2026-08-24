# SentinelLLM

SentinelLLM is a contract-driven security scanner for AI/LLM applications.

SentinelLLM performs bounded, auditable security assessments of HTTP-based AI/LLM
applications. It discovers the configured target, plans OWASP GenAI LLM Top 10 2026
tests, executes every request through a deterministic policy gate, adapts follow-up
strategies from observed responses, verifies candidate findings, and writes separate
security and attack-journey reports.

## Installation

Python 3.11 or later is required.

```bash
python -m pip install -e ".[dev]"
```

## Development

```bash
pytest
ruff check .
mypy .
```

Run the CLI:

```bash
sentinelllm scan --target http://127.0.0.1:8000
sentinelllm scan --config configs/example_scan.yaml
```

Run the deterministic local demonstration in two terminals:

```bash
python -m demo.target_app --port 8765
sentinelllm scan --config configs/demo_scan.yaml
```

Direct `--target` scans and configurations with `dry_run: true` validate and initialize
a pending scan without sending traffic. Set `scan.dry_run: false` in YAML only for an
authorized target. Completed scans write a scan-ID directory under the configured report
directory containing:

- `sentinelllm_security_report.html` and `.json`: verified vulnerabilities, severity,
  confidence, all-category coverage, evidence IDs, and remediation.
- `sentinelllm_attack_report.html` and `.json`: jobs, normalized responses, observations,
  judgments, hypothesis changes, strategy transitions, verification, and cost statistics.

Non-dry-run CLI scans also persist complete typed snapshots in
`sentinelllm_history.sqlite3` under the configured report root. Reports for earlier scan IDs
are retained.

## Configuration and secrets

Target credentials and provider API keys are referenced by environment-variable name. Secret
values are never stored in `ScanConfiguration`, scan history, or reports. Configure target
authentication under `target.authentication` and provider settings under `llm`; see
`configs/example_scan.yaml` for the complete schema.

`deterministic` is the default provider and requires no external service. Dedicated adapters
support `openai_compatible`, `azure_openai`, and `anthropic` request and response protocols;
`http_json` and `local_json` support generic structured endpoints.
Required fields and allowed decision/strategy values are validated before use. Timeouts,
unavailable providers, malformed output, and out-of-schema values fall back to deterministic
selection and are recorded in adaptation metadata. Providers may assist hypothesis formulation,
ambiguous-response judging, and next-strategy selection. They cannot create evidence, execute
target requests, or alter policy limits.

## Discovery

Discovery profiles the configured endpoint and may retrieve configured same-origin API documents
such as `/openapi.json` and `/swagger.json`. It parses OpenAPI methods, request-body fields,
parameters, and content types, plus named inputs from same-origin HTML forms. External form
actions and endpoints are discarded. The Planner uses discovered writable endpoints, methods,
and parameters when constructing attacks instead of always targeting the root URL.

## OWASP 2026 coverage

The checked-in `OWASP-GenAI-LLM-Top-10-2026-v1.0.pdf` is the taxonomy source. SentinelLLM
registers five category-specific strategies for each category: Prompt Injection, Sensitive Information
Disclosure, Excessive Agency, Supply Chain, Data and Model Poisoning, Unbounded Consumption,
Misinformation, Hidden Context Exposure, Vector and Embedding Weaknesses, and Improper Output
Handling. A category without an executed job is reported as `not_tested`, never secure.

## Adaptive execution

The Agent creates an initial job from the Target Profile and Strategy Registry. The
Orchestrator applies scope, method, duplicate, iteration, endpoint, job, and request budgets
before the Executor uses the Connector. The Connector independently enforces an actual request
ceiling across retries, session cookies, concurrency, pacing, and timeouts. Structured response
analysis records status, redirects, authentication changes, response structure, tool/action/state
signals, reflection, relevant errors, and baseline deviations. The Judge then switches,
refines, verifies, or stops and records concise decision metadata. Important state is held in
`ScanHistory`, not model conversation memory.

Potential success is not a confirmed finding. Distinct jobs using at least two distinct strategies
must reproduce the signal before `DefaultVerificationComponent` marks it verified and the
security report includes it. Cancelling the async scan persists a `cancelled` history snapshot,
generates partial reports, and propagates cancellation to the caller.

The adaptive HTML report provides expandable request/response evidence plus timeline search and
category/outcome filters. Both reports remain self-contained and require no external assets.

## Extending

- Add a strategy by constructing `AttackStrategy` and registering it with `StrategyRegistry`.
- Add a connector by implementing async `TargetConnector.send`; no other component owns I/O.
- Use `SQLiteHistoryStore` for durable local history or implement `HistoryStore` for another
  database.
- Add an LLM provider by implementing `LLMProvider.complete`; deterministic policy remains the
  final authority and must not be provider-controlled.

See [docs/architecture.md](docs/architecture.md) for component responsibilities and testing.
