"""Conservative target discovery through the configured connector."""

from urllib.parse import urljoin

from sentinelllm.connector.base import TargetConnector
from sentinelllm.core.models import EndpointProfile, ScanConfiguration, TargetProfile
from sentinelllm.discovery.base import DiscoveryAgent
from sentinelllm.discovery.parsers import parse_html_forms, parse_openapi


class DefaultDiscoveryAgent(DiscoveryAgent):
    """Build a profile from a non-mutating baseline request."""

    async def discover(
        self, configuration: ScanConfiguration, connector: TargetConnector
    ) -> TargetProfile:
        """Observe the configured interface without probing unrelated paths."""
        response = await connector.send(
            {
                "method": "GET",
                "url": configuration.target_url,
                "headers": {"Accept": "application/json, text/plain, text/html"},
            }
        )
        body = (response.body or "").lower()
        headers = {key.lower(): value for key, value in response.headers.items()}
        llm_signals = ("model", "chat", "prompt", "completion", "assistant")
        rag_signals = ("retrieval", "knowledge base", "sources", "citations")
        tool_signals = ("tool", "function", "plugin", "action")
        reachable = response.status_code is not None
        capabilities = tuple(
            name
            for name, present in (
                ("llm", any(signal in body for signal in llm_signals)),
                ("retrieval", any(signal in body for signal in rag_signals)),
                ("tools", any(signal in body for signal in tool_signals)),
                ("structured_output", "json" in str(response.metadata.get("content_type", ""))),
            )
            if present
        )
        endpoint_profiles: list[EndpointProfile] = [
            EndpointProfile(
                configuration.target_url,
                "GET",
                content_types=(str(response.metadata.get("content_type", "")),),
            )
        ]
        endpoint_profiles.extend(parse_openapi(configuration.target_url, response.body or ""))
        endpoint_profiles.extend(parse_html_forms(configuration.target_url, response.body or ""))
        discovery_request_count = 1
        for path in configuration.discovery_paths:
            document_url = urljoin(configuration.target_url.rstrip("/") + "/", path.lstrip("/"))
            document_response = await connector.send(
                {
                    "method": "GET",
                    "url": document_url,
                    "headers": {"Accept": "application/json"},
                }
            )
            discovery_request_count += 1
            if document_response.status_code == 200:
                endpoint_profiles.extend(
                    parse_openapi(configuration.target_url, document_response.body or "")
                )
        endpoint_profiles = list(
            {(item.url, item.method, item.parameters): item for item in endpoint_profiles}.values()
        )
        return TargetProfile(
            target_url=configuration.target_url,
            application_name=headers.get("server"),
            has_llm=any(signal in body for signal in llm_signals) if reachable else None,
            has_rag=any(signal in body for signal in rag_signals) if reachable else None,
            has_tools=any(signal in body for signal in tool_signals) if reachable else None,
            authentication_required=response.status_code in {401, 403},
            identified_endpoints=tuple(dict.fromkeys(item.url for item in endpoint_profiles)),
            endpoint_profiles=tuple(endpoint_profiles),
            interfaces=("http",) if reachable else (),
            capabilities=capabilities,
            attack_surface=("http",) if reachable else (),
            technology=tuple(
                item
                for item in (
                    headers.get("server"),
                    str(response.metadata.get("content_type", "")) or None,
                )
                if item
            ),
            discovery_evidence=(
                f"baseline status={response.status_code}",
                f"capabilities={','.join(capabilities) or 'none observed'}",
                f"endpoint_profiles={len(endpoint_profiles)}",
            ),
            discovery_metadata={
                "baseline_status": response.status_code,
                "content_type": response.metadata.get("content_type"),
                "reachable": reachable,
                "baseline_body": (response.body or "")[:2000],
                "baseline_headers": headers,
                "request_count": discovery_request_count,
            },
        )
