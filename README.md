# SentinelLLM

SentinelLLM is a contract-driven security scanner for AI/LLM applications.

## Current status

Phase 1 provides the architectural foundation only: typed domain models, component
contracts, dependency injection, a pending-scan CLI, configuration loading, and tests.
It does not perform discovery, generate or execute attacks, judge results, or produce
security findings.

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

## Future phases

Future work will implement controlled target discovery, OWASP-aligned planning,
execution, verification, evaluation, durable history stores, and reports behind the
contracts established in this phase.
