"""Production discovery placeholder."""

from sentinelllm.connector.base import TargetConnector
from sentinelllm.core.errors import FeatureNotImplementedError
from sentinelllm.core.models import ScanConfiguration, TargetProfile
from sentinelllm.discovery.base import DiscoveryAgent


class DefaultDiscoveryAgent(DiscoveryAgent):
    """Clearly unimplemented production discovery agent."""

    async def discover(
        self, configuration: ScanConfiguration, connector: TargetConnector
    ) -> TargetProfile:
        """Raise rather than inventing a target profile."""
        raise FeatureNotImplementedError("Target discovery is not implemented in Phase 1")
