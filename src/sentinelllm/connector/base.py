"""Target connector boundary."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class TargetResponse:
    """Transport-level response exposed to discovery and execution components."""

    status_code: int | None
    body: str | None
    headers: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class TargetConnector(ABC):
    """Asynchronous boundary for communicating with an authorized target."""

    @abstractmethod
    async def send(self, request: dict[str, Any]) -> TargetResponse:
        """Send a structured target request and return its transport response."""
        raise NotImplementedError
