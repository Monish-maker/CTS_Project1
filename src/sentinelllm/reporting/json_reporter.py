"""JSON report placeholder."""

from pathlib import Path

from sentinelllm.core.errors import FeatureNotImplementedError
from sentinelllm.core.models import ScanHistory
from sentinelllm.reporting.base import ReportGenerator


class JsonReportGenerator(ReportGenerator):
    """Clearly unimplemented JSON report generator."""

    def generate(self, history: ScanHistory, output_directory: Path) -> Path:
        """Raise rather than producing an incomplete security report."""
        raise FeatureNotImplementedError("JSON reporting is not implemented in Phase 1")
