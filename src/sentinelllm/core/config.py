"""Configuration loading isolated from CLI and scan components."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from sentinelllm.core.enums import AttackCategory
from sentinelllm.core.errors import ConfigurationError
from sentinelllm.core.models import (
    AuthenticationConfiguration,
    LLMConfiguration,
    RetryConfiguration,
    ScanConfiguration,
)


def load_scan_configuration(path: Path) -> ScanConfiguration:
    """Load a scan configuration from a YAML document."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError as error:
        raise ConfigurationError(f"unable to read configuration: {path}") from error
    except yaml.YAMLError as error:
        raise ConfigurationError("configuration is not valid YAML") from error
    return scan_configuration_from_mapping(raw)


def scan_configuration_from_mapping(raw: dict[str, Any]) -> ScanConfiguration:
    """Translate the external YAML schema into the internal typed configuration."""
    target = raw.get("target", {})
    scan = raw.get("scan", {})
    attacks = raw.get("attacks", {})
    reporting = raw.get("reporting", {})
    authentication = target.get("authentication", {})
    llm = raw.get("llm", {})
    try:
        categories = tuple(AttackCategory(value) for value in attacks.get("enabled", []))
        target_headers = {
            str(key): str(value) for key, value in target.get("headers", {}).items()
        }
        return ScanConfiguration(
            target_url=target["url"],
            target_headers=target_headers,
            authentication=AuthenticationConfiguration(
                required=bool(authentication.get("required", False)),
                scheme=str(authentication["scheme"]) if authentication.get("scheme") else None,
                header_name=str(authentication.get("header_name", "Authorization")),
                environment_variable=str(authentication["environment_variable"])
                if authentication.get("environment_variable")
                else None,
            ),
            llm=LLMConfiguration(
                provider=str(llm.get("provider", "deterministic")),
                model=str(llm.get("model", "")),
                endpoint=str(llm["endpoint"]) if llm.get("endpoint") else None,
                api_key_environment_variable=(
                    str(llm["api_key_environment_variable"])
                    if llm.get("api_key_environment_variable")
                    else None
                ),
                timeout_seconds=float(llm.get("timeout", 20)),
                maximum_retries=int(llm.get("retries", 1)),
            ),
            timeout_seconds=float(scan.get("timeout", 10)),
            retry=RetryConfiguration(attempts=int(scan.get("retries", 2))),
            enabled_attack_categories=categories,
            maximum_attack_iterations=int(scan.get("max_iterations", 5)),
            maximum_jobs=int(scan.get("max_jobs", 50)),
            maximum_requests=int(scan.get("max_requests", 50)),
            maximum_requests_per_endpoint=int(scan.get("max_requests_per_endpoint", 10)),
            maximum_scan_duration_seconds=float(scan.get("max_duration_seconds", 300)),
            allowed_methods=tuple(
                str(item).upper() for item in scan.get("allowed_methods", ["GET", "POST"])
            ),
            concurrency=int(scan.get("concurrency", 1)),
            minimum_request_interval_seconds=float(scan.get("minimum_request_interval_seconds", 0)),
            discovery_paths=tuple(
                str(item)
                for item in scan.get("discovery_paths", ["/openapi.json", "/swagger.json"])
            ),
            dry_run=bool(scan.get("dry_run", True)),
            reporting_output_directory=str(reporting.get("output_directory", "./reports")),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ConfigurationError("configuration has missing or invalid values") from error
