"""End-to-end test through the real HTTP connector and local demo target."""

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urljoin

from demo.target_app import create_server
from sentinelllm.attacks.agent import DefaultAttackAgent
from sentinelllm.attacks.executor import DefaultAttackExecutor
from sentinelllm.connector.http import HttpTargetConnector
from sentinelllm.core.enums import AttackCategory, ScanStatus
from sentinelllm.core.models import ScanConfiguration
from sentinelllm.discovery.discovery_agent import DefaultDiscoveryAgent
from sentinelllm.evaluation.evaluator import DefaultFinalEvaluator
from sentinelllm.history.store import SQLiteHistoryStore
from sentinelllm.judging.judge import DefaultAttackJudge
from sentinelllm.orchestrator.scan_orchestrator import ScanOrchestrator
from sentinelllm.planning.attack_planner import DefaultAttackPlanner
from sentinelllm.reporting.bundle import ReportBundleGenerator
from sentinelllm.verification.verifier import DefaultVerificationComponent


def test_real_http_demo_scan_generates_verified_reports(tmp_path: Path) -> None:
    server = create_server(port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}"
        configuration = ScanConfiguration(
            target_url=target,
            enabled_attack_categories=(AttackCategory.PROMPT_INJECTION,),
            maximum_attack_iterations=5,
            maximum_jobs=10,
            maximum_requests=10,
            maximum_requests_per_endpoint=10,
            dry_run=False,
            reporting_output_directory=str(tmp_path),
        )
        store = SQLiteHistoryStore(tmp_path / "history.sqlite3")
        orchestrator = ScanOrchestrator(
            connector=HttpTargetConnector(timeout_seconds=2, retries=0),
            discovery=DefaultDiscoveryAgent(),
            planner=DefaultAttackPlanner(),
            attack_agent=DefaultAttackAgent(),
            executor=DefaultAttackExecutor(),
            judge=DefaultAttackJudge(),
            verifier=DefaultVerificationComponent(),
            evaluator=DefaultFinalEvaluator(),
            history=store,
            reporter=ReportBundleGenerator(),
        )

        history = asyncio.run(orchestrator.run(configuration))

        assert history.status is ScanStatus.COMPLETED
        assert history.findings
        assert history.target_profile is not None
        assert any(item.url.endswith("/chat") for item in history.target_profile.endpoint_profiles)
        assert all(job.request["url"].endswith("/chat") for job in history.jobs)
        assert all("prompt" in job.request["json"] for job in history.jobs)
        assert store.get_scan(configuration.scan_id) == history
        assert len(list((tmp_path / configuration.scan_id).glob("sentinelllm_*_report.*"))) == 4
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_connector_records_redirect_without_following_destination() -> None:
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "https://outside.test/collect")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = urljoin(f"http://127.0.0.1:{server.server_port}", "/redirect")
        response = asyncio.run(HttpTargetConnector(retries=0).send({"url": url}))
        assert response.status_code == 302
        assert response.headers["Location"] == "https://outside.test/collect"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
