"""Configuration loading isolated from CLI and scan components."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from sentinelllm.core.enums import AttackCategory
from sentinelllm.core.errors import ConfigurationError
from sentinelllm.core.models import RetryConfiguration, ScanConfiguration


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
    try:
        categories = tuple(AttackCategory(value) for value in attacks.get("enabled", []))
        return ScanConfiguration(
            target_url=target["url"],
            timeout_seconds=float(scan.get("timeout", 10)),
            retry=RetryConfiguration(attempts=int(scan.get("retries", 2))),
            enabled_attack_categories=categories,
            maximum_attack_iterations=int(scan.get("max_iterations", 5)),
            dry_run=bool(scan.get("dry_run", True)),
            reporting_output_directory=str(reporting.get("output_directory", "./reports")),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ConfigurationError("configuration has missing or invalid values") from error
