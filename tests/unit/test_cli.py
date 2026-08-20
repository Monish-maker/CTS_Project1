"""CLI help and pending-scan tests."""

import pytest

from sentinelllm.cli import main


@pytest.mark.parametrize("arguments", [["--help"], ["scan", "--help"]])
def test_help_commands_exit_successfully(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as result:
        main(arguments)

    assert result.value.code == 0
    assert "usage:" in capsys.readouterr().out


def test_scan_initializes_pending_record(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--target", "http://127.0.0.1:8000"]) == 0
    assert ": pending" in capsys.readouterr().out
