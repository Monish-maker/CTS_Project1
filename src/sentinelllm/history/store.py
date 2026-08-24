"""History persistence boundary and a process-local implementation."""

import sqlite3
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path

from sentinelllm.core.models import ScanConfiguration, ScanHistory
from sentinelllm.history.serialization import deserialize_history, serialize_history


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

    def save_scan(self, history: ScanHistory) -> ScanHistory:
        """Persist an updated aggregate; stores may override for durability."""
        return history


class InMemoryHistoryStore(HistoryStore):
    """Non-durable structured store suitable for local scans and tests."""

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

    def save_scan(self, history: ScanHistory) -> ScanHistory:
        """Atomically replace the aggregate for one scan."""
        self._scans[history.scan.scan_id] = history
        return history


class SQLiteHistoryStore(HistoryStore):
    """Durable SQLite store retaining complete structured history snapshots."""

    def __init__(self, database_path: Path) -> None:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._database_path = database_path
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    scan_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def start_scan(self, configuration: ScanConfiguration) -> ScanHistory:
        return self.save_scan(ScanHistory(scan=configuration))

    def get_scan(self, scan_id: str) -> ScanHistory | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM scan_history WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return deserialize_history(str(row[0])) if row else None

    def save_scan(self, history: ScanHistory) -> ScanHistory:
        payload = serialize_history(history)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scan_history(scan_id, payload, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (history.scan.scan_id, payload, datetime.now(UTC).isoformat()),
            )
        return history

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._database_path)
