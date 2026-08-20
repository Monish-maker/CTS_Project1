"""History persistence boundary and a process-local Phase 1 implementation."""

from abc import ABC, abstractmethod

from sentinelllm.core.models import ScanConfiguration, ScanHistory


class HistoryStore(ABC):
    """Persistence boundary replaceable with SQLite, PostgreSQL, or another store."""

    @abstractmethod
    def start_scan(self, configuration: ScanConfiguration) -> ScanHistory:
        """Persist the initial record for a new scan."""
        raise NotImplementedError

    @abstractmethod
    def get_scan(self, scan_id: str) -> ScanHistory | None:
        """Retrieve one scan lifecycle record."""
        raise NotImplementedError


class InMemoryHistoryStore(HistoryStore):
    """Non-durable store suitable only for Phase 1 wiring and tests."""

    def __init__(self) -> None:
        self._scans: dict[str, ScanHistory] = {}

    def start_scan(self, configuration: ScanConfiguration) -> ScanHistory:
        """Create and retain the initial pending scan record."""
        history = ScanHistory(scan=configuration)
        self._scans[configuration.scan_id] = history
        return history

    def get_scan(self, scan_id: str) -> ScanHistory | None:
        """Return a scan record if it exists in this process."""
        return self._scans.get(scan_id)
