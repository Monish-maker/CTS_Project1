"""Command-line entry point for initializing SentinelLLM scans."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Sequence
from pathlib import Path

from sentinelllm.attacks.agent import DefaultAttackAgent
from sentinelllm.attacks.executor import DefaultAttackExecutor
from sentinelllm.connector.http import HttpTargetConnector
from sentinelllm.core.config import load_scan_configuration
from sentinelllm.core.errors import ConfigurationError
from sentinelllm.core.logging import configure_logging
from sentinelllm.core.models import ScanConfiguration
from sentinelllm.discovery.discovery_agent import DefaultDiscoveryAgent
from sentinelllm.evaluation.evaluator import DefaultFinalEvaluator
from sentinelllm.history.store import InMemoryHistoryStore, SQLiteHistoryStore
from sentinelllm.judging.judge import DefaultAttackJudge
from sentinelllm.llm.provider import build_llm_provider
from sentinelllm.orchestrator.scan_orchestrator import ScanOrchestrator
from sentinelllm.planning.attack_planner import DefaultAttackPlanner
from sentinelllm.reporting.bundle import ReportBundleGenerator
from sentinelllm.verification.verifier import DefaultVerificationComponent


def build_parser() -> argparse.ArgumentParser:
    """Build the SentinelLLM argument parser."""
    parser = argparse.ArgumentParser(prog="sentinelllm")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="run a bounded SentinelLLM scan")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--target", help="HTTP(S) target URL")
    source.add_argument("--config", type=Path, help="path to YAML scan configuration")
    return parser


def build_orchestrator(configuration: ScanConfiguration | None = None) -> ScanOrchestrator:
    """Compose production components behind the established contracts."""
    configuration = configuration or ScanConfiguration(target_url="http://127.0.0.1")
    authentication_headers = _authentication_headers(configuration)
    provider = build_llm_provider(configuration.llm)
    history = (
        InMemoryHistoryStore()
        if configuration.dry_run
        else SQLiteHistoryStore(
            Path(configuration.reporting_output_directory) / "sentinelllm_history.sqlite3"
        )
    )
    return ScanOrchestrator(
        connector=HttpTargetConnector(
            timeout_seconds=configuration.timeout_seconds,
            retries=configuration.retry.attempts,
            default_headers=authentication_headers,
            concurrency=configuration.concurrency,
            minimum_request_interval_seconds=configuration.minimum_request_interval_seconds,
            maximum_requests=configuration.maximum_requests,
        ),
        discovery=DefaultDiscoveryAgent(),
        planner=DefaultAttackPlanner(),
        attack_agent=DefaultAttackAgent(provider=provider),
        executor=DefaultAttackExecutor(),
        judge=DefaultAttackJudge(provider=provider),
        verifier=DefaultVerificationComponent(),
        evaluator=DefaultFinalEvaluator(),
        history=history,
        reporter=ReportBundleGenerator(),
    )


def _authentication_headers(configuration: ScanConfiguration) -> dict[str, str]:
    authentication = configuration.authentication
    if not authentication.environment_variable:
        if authentication.required:
            raise ConfigurationError("target authentication environment variable is required")
        return {}
    secret = os.environ.get(authentication.environment_variable)
    if not secret:
        if authentication.required:
            raise ConfigurationError(
                "target authentication environment variable is not set: "
                f"{authentication.environment_variable}"
            )
        return {}
    value = f"{authentication.scheme} {secret}" if authentication.scheme else secret
    return {authentication.header_name: value}


def main(argv: Sequence[str] | None = None) -> int:
    """Parse a command, validating composition in dry-run mode or running a scan."""
    configure_logging()
    arguments = build_parser().parse_args(argv)
    configuration = (
        load_scan_configuration(arguments.config)
        if arguments.config is not None
        else ScanConfiguration(target_url=arguments.target)
    )
    orchestrator = build_orchestrator(configuration)
    scan_history = (
        orchestrator.start(configuration)
        if configuration.dry_run
        else asyncio.run(orchestrator.run(configuration))
    )
    print(f"Scan {scan_history.scan.scan_id}: {scan_history.status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
