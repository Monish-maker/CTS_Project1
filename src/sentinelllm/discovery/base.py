"""Discovery component boundary."""

from abc import ABC, abstractmethod

from sentinelllm.connector.base import TargetConnector
from sentinelllm.core.models import ScanConfiguration, TargetProfile


class DiscoveryAgent(ABC):
    """Discovers a target profile through an authorized connector."""

    @abstractmethod
    async def discover(
        self, configuration: ScanConfiguration, connector: TargetConnector
    ) -> TargetProfile:
        """Build a target profile from permitted discovery operations."""
        raise NotImplementedError
