"""Command-line entry point for initializing SentinelLLM scans."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from sentinelllm.attacks.agent import DefaultAttackAgent
from sentinelllm.attacks.executor import DefaultAttackExecutor
from sentinelllm.connector.http import HttpTargetConnector
from sentinelllm.core.config import load_scan_configuration
from sentinelllm.core.logging import configure_logging
from sentinelllm.core.models import ScanConfiguration
from sentinelllm.discovery.discovery_agent import DefaultDiscoveryAgent
from sentinelllm.evaluation.evaluator import DefaultFinalEvaluator
from sentinelllm.history.store import InMemoryHistoryStore
from sentinelllm.judging.judge import DefaultAttackJudge
from sentinelllm.orchestrator.scan_orchestrator import ScanOrchestrator
from sentinelllm.planning.attack_planner import DefaultAttackPlanner
from sentinelllm.reporting.json_reporter import JsonReportGenerator
from sentinelllm.verification.verifier import DefaultVerificationComponent


def build_parser() -> argparse.ArgumentParser:
    """Build the SentinelLLM argument parser."""
    parser = argparse.ArgumentParser(prog="sentinelllm")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="initialize a Phase 1 scan")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--target", help="HTTP(S) target URL")
    source.add_argument("--config", type=Path, help="path to YAML scan configuration")
    return parser


def build_orchestrator() -> ScanOrchestrator:
    """Compose explicit Phase 1 placeholders behind the orchestrator contracts."""
    return ScanOrchestrator(
        connector=HttpTargetConnector(),
        discovery=DefaultDiscoveryAgent(),
        planner=DefaultAttackPlanner(),
        attack_agent=DefaultAttackAgent(),
        executor=DefaultAttackExecutor(),
        judge=DefaultAttackJudge(),
        verifier=DefaultVerificationComponent(),
        evaluator=DefaultFinalEvaluator(),
        history=InMemoryHistoryStore(),
        reporter=JsonReportGenerator(),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Parse a command and initialize a pending Phase 1 scan."""
    configure_logging()
    arguments = build_parser().parse_args(argv)
    configuration = (
        load_scan_configuration(arguments.config)
        if arguments.config is not None
        else ScanConfiguration(target_url=arguments.target)
    )
    scan_history = build_orchestrator().start(configuration)
    print(f"Scan {scan_history.scan.scan_id}: {scan_history.status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
