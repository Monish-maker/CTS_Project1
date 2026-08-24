"""Composite report generator for all required artifacts."""

from pathlib import Path

from sentinelllm.core.models import ScanHistory
from sentinelllm.reporting.base import ReportGenerator
from sentinelllm.reporting.html_reporter import HtmlReportGenerator
from sentinelllm.reporting.json_reporter import JsonReportGenerator


class ReportBundleGenerator(ReportGenerator):
    """Generate separate security and adaptive reports in HTML and JSON."""

    def generate(self, history: ScanHistory, output_directory: Path) -> Path:
        JsonReportGenerator().generate(history, output_directory)
        return HtmlReportGenerator().generate(history, output_directory)
