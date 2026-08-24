"""CLI help and pending-scan tests."""

import pytest

from sentinelllm.cli import _authentication_headers, main
from sentinelllm.core.errors import ConfigurationError
from sentinelllm.core.models import AuthenticationConfiguration, ScanConfiguration


@pytest.mark.parametrize("arguments", [["--help"], ["scan", "--help"]])
def test_help_commands_exit_successfully(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as result:
        main(arguments)

    assert result.value.code == 0
    assert "usage:" in capsys.readouterr().out


def test_scan_initializes_pending_record(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--target", "http://127.0.0.1:8000"]) == 0
    assert ": pending" in capsys.readouterr().out


def test_authentication_uses_environment_without_persisting_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_TEST_TOKEN", "secret-value")
    configuration = ScanConfiguration(
        target_url="https://example.test",
        authentication=AuthenticationConfiguration(
            required=True,
            scheme="Bearer",
            environment_variable="SENTINEL_TEST_TOKEN",
        ),
    )

    headers = _authentication_headers(configuration)

    assert headers == {"Authorization": "Bearer secret-value"}
    assert "secret-value" not in str(configuration.to_dict())


def test_required_authentication_rejects_missing_environment_secret() -> None:
    configuration = ScanConfiguration(
        target_url="https://example.test",
        authentication=AuthenticationConfiguration(
            required=True,
            environment_variable="SENTINEL_MISSING_TOKEN",
        ),
    )
    with pytest.raises(ConfigurationError, match="not set"):
        _authentication_headers(configuration)
