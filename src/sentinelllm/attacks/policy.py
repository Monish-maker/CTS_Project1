"""Deterministic policy gate between attack generation and execution."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from urllib.parse import urljoin, urlparse

from sentinelllm.core.models import AttackJob, PolicyDecision, ScanConfiguration


class AttackPolicy:
    """Validate scope, methods, budgets, and duplicate attack fingerprints."""

    def __init__(self, configuration: ScanConfiguration) -> None:
        self._configuration = configuration
        self._fingerprints: set[str] = set()
        self._endpoint_requests: Counter[str] = Counter()
        self._requests = 0

    def validate(self, job: AttackJob) -> PolicyDecision:
        request = job.request
        method = str(request.get("method", "POST")).upper()
        url = urljoin(
            self._configuration.target_url, str(request.get("url", request.get("path", "")))
        )
        fingerprint = self.fingerprint(job, url, method)
        reason = self._rejection_reason(job, url, method, fingerprint)
        approved = reason is None
        if approved:
            self._fingerprints.add(fingerprint)
            self._endpoint_requests[urlparse(url).path or "/"] += 1
            self._requests += 1
        return PolicyDecision(job.job_id, approved, reason or "approved", fingerprint)

    def fingerprint(self, job: AttackJob, url: str, method: str) -> str:
        material = {
            "attack_id": job.attack_id,
            "strategy": job.metadata.get("strategy_id", ""),
            "url": url,
            "method": method,
            "parameter": job.metadata.get("parameter", ""),
            "payload": job.request.get("json", job.request.get("body", "")),
        }
        normalized = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def _rejection_reason(
        self, job: AttackJob, url: str, method: str, fingerprint: str
    ) -> str | None:
        configured = urlparse(self._configuration.target_url)
        proposed = urlparse(url)
        if proposed.scheme not in {"http", "https"} or proposed.netloc != configured.netloc:
            return "target is outside configured scope"
        if method not in {item.upper() for item in self._configuration.allowed_methods}:
            return "HTTP method is not allowed"
        if job.iteration > self._configuration.maximum_attack_iterations:
            return "iteration budget exhausted"
        if self._requests >= min(
            self._configuration.maximum_requests, self._configuration.maximum_jobs
        ):
            return "scan request budget exhausted"
        if (
            self._endpoint_requests[proposed.path or "/"]
            >= self._configuration.maximum_requests_per_endpoint
        ):
            return "endpoint request budget exhausted"
        if fingerprint in self._fingerprints:
            return "duplicate attack fingerprint"
        return None
