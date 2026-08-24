"""JSON report generators."""

import json
from datetime import date, datetime
from enum import Enum
from pathlib import Path

from sentinelllm.core.models import ScanHistory
from sentinelllm.reporting.base import ReportGenerator
from sentinelllm.reporting.data import attack_report_data, security_report_data


class JsonReportGenerator(ReportGenerator):
    """Generate separate security and adaptive attack JSON reports."""

    def generate(self, history: ScanHistory, output_directory: Path) -> Path:
        """Write both JSON projections and return the security report path."""
        output_directory.mkdir(parents=True, exist_ok=True)
        security_path = output_directory / "sentinelllm_security_report.json"
        attack_path = output_directory / "sentinelllm_attack_report.json"
        security_path.write_text(
            json.dumps(security_report_data(history), indent=2, default=_json_default),
            encoding="utf-8",
        )
        attack_path.write_text(
            json.dumps(attack_report_data(history), indent=2, default=_json_default),
            encoding="utf-8",
        )
        return security_path


def _json_default(value: object) -> object:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    return str(value)
