"""Report generator boundary."""

from abc import ABC, abstractmethod
from pathlib import Path

from sentinelllm.core.models import ScanHistory


class ReportGenerator(ABC):
    """Generates a report representation from recorded scan history."""

    @abstractmethod
    def generate(self, history: ScanHistory, output_directory: Path) -> Path:
        """Write a report and return its path."""
        raise NotImplementedError
