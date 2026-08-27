"""Unit tests for core domain models and configuration parsing."""

import pytest

from sentinelllm.core.config import scan_configuration_from_mapping
from sentinelllm.core.enums import AttackCategory, JudgeOutcome, ScanStatus
from sentinelllm.core.errors import ConfigurationError
from sentinelllm.core.models import JudgeResult, ScanConfiguration


def test_scan_configuration_creation_and_serialization() -> None:
    configuration = ScanConfiguration(target_url="https://example.test")

    serialized = configuration.to_dict()

    assert serialized["target_url"] == "https://example.test"
    assert serialized["dry_run"] is True
    assert configuration.scan_id


def test_invalid_target_url_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="http or https"):
        ScanConfiguration(target_url="ftp://example.test")


def test_yaml_mapping_converts_enabled_categories() -> None:
    configuration = scan_configuration_from_mapping(
        {
            "target": {
                "url": "http://127.0.0.1:8000",
                "headers": {"anthropic-version": "2023-06-01"},
                "request": {
                    "format": "anthropic_messages",
                    "model": "claude-3-5-sonnet-latest",
                    "max_tokens": 512,
                },
            },
            "attacks": {"enabled": ["prompt_injection"]},
        }
    )

    assert configuration.enabled_attack_categories == (AttackCategory.PROMPT_INJECTION,)
    assert configuration.target_headers == {"anthropic-version": "2023-06-01"}
    assert configuration.target_request.format == "anthropic_messages"
    assert configuration.target_request.model == "claude-3-5-sonnet-latest"
    assert configuration.target_request.max_tokens == 512


def test_enum_values_are_stable() -> None:
    assert JudgeOutcome.INCONCLUSIVE.value == "inconclusive"
    assert ScanStatus.PENDING.value == "pending"
    assert len(set(AttackCategory)) == 10
    assert AttackCategory.IMPROPER_OUTPUT_HANDLING.value == "improper_output_handling"


def test_judge_confidence_must_be_normalized() -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        JudgeResult(outcome=JudgeOutcome.FAILED, confidence=1.1, reason="invalid")
