"""HTTP connector placeholder for a future controlled transport implementation."""

from typing import Any

from sentinelllm.connector.base import TargetConnector, TargetResponse
from sentinelllm.core.errors import FeatureNotImplementedError


class HttpTargetConnector(TargetConnector):
    """HTTP/HTTPS connector contract implementation reserved for a later phase."""

    async def send(self, request: dict[str, Any]) -> TargetResponse:
        """Reject requests until target authorization and transport policy exist."""
        raise FeatureNotImplementedError("HTTP target communication is not implemented in Phase 1")
