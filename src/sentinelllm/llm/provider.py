"""Validated structured-output LLM provider boundary and safe implementations."""

from __future__ import annotations

import asyncio
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sentinelllm.core.models import LLMConfiguration


class LLMProviderError(Exception):
    """A bounded provider failure that callers may safely fall back from."""


@dataclass(frozen=True, slots=True)
class StructuredLLMRequest:
    """Provider-neutral reasoning request with an explicit output contract."""

    task: str
    context: dict[str, Any]
    allowed_values: dict[str, tuple[str, ...]]
    required_fields: tuple[str, ...]


class LLMProvider(ABC):
    """Returns validated metadata and never executes target requests."""

    @abstractmethod
    async def complete(self, request: StructuredLLMRequest) -> dict[str, Any]:
        """Return a schema-constrained decision or raise a bounded provider error."""
        raise NotImplementedError


class DeterministicLLMProvider(LLMProvider):
    """Safe fallback indicating that deterministic scanner logic should decide."""

    async def complete(self, request: StructuredLLMRequest) -> dict[str, Any]:
        return {"fallback": True, "reason": "deterministic provider configured"}


class HttpJSONLLMProvider(LLMProvider):
    """Generic JSON provider isolated from target transport and execution policy."""

    def __init__(self, configuration: LLMConfiguration, protocol: str = "generic") -> None:
        if not configuration.endpoint:
            raise LLMProviderError("LLM endpoint is required for an HTTP provider")
        self._configuration = configuration
        self._protocol = protocol

    async def complete(self, request: StructuredLLMRequest) -> dict[str, Any]:
        last_error = "provider unavailable"
        for _ in range(self._configuration.maximum_retries + 1):
            try:
                response = await asyncio.wait_for(
                    asyncio.to_thread(self._complete_sync, request),
                    timeout=self._configuration.timeout_seconds,
                )
                return validate_structured_output(request, response)
            except (
                TimeoutError,
                HTTPError,
                URLError,
                OSError,
                ValueError,
                LLMProviderError,
            ) as error:
                last_error = f"{type(error).__name__}: {error}"
        raise LLMProviderError(last_error)

    def _complete_sync(self, request: StructuredLLMRequest) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        environment_name = self._configuration.api_key_environment_variable
        api_key = os.environ.get(environment_name, "") if environment_name else ""
        if environment_name and not api_key:
            raise LLMProviderError(
                f"LLM credential environment variable is not set: {environment_name}"
            )
        headers.update(self._authentication_headers(api_key))
        body = json.dumps(self._request_payload(request)).encode("utf-8")
        prepared = Request(str(self._configuration.endpoint), body, headers, method="POST")
        with urlopen(  # noqa: S310
            prepared, timeout=self._configuration.timeout_seconds
        ) as response:
            parsed = json.loads(response.read().decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("LLM output must be a JSON object")
        candidate = self._extract_candidate(parsed)
        if not isinstance(candidate, dict):
            raise ValueError("LLM structured output must be a JSON object")
        return candidate

    def _authentication_headers(self, api_key: str) -> dict[str, str]:
        if not api_key:
            return {}
        if self._protocol == "azure_openai":
            return {"api-key": api_key}
        if self._protocol == "anthropic":
            return {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
        return {"Authorization": f"Bearer {api_key}"}

    def _request_payload(self, request: StructuredLLMRequest) -> dict[str, Any]:
        contract = {
            "task": request.task,
            "context": request.context,
            "output_schema": {
                "required": request.required_fields,
                "allowed_values": request.allowed_values,
            },
        }
        if self._protocol in {"openai_compatible", "azure_openai"}:
            return {
                "model": self._configuration.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "Return only one JSON object matching the supplied contract.",
                    },
                    {"role": "user", "content": json.dumps(contract)},
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0,
            }
        if self._protocol == "anthropic":
            return {
                "model": self._configuration.model,
                "max_tokens": 1024,
                "temperature": 0,
                "system": "Return only one JSON object matching the supplied contract.",
                "messages": [{"role": "user", "content": json.dumps(contract)}],
            }
        return {"model": self._configuration.model, **contract}

    def _extract_candidate(self, parsed: dict[str, Any]) -> Any:
        if self._protocol in {"openai_compatible", "azure_openai"}:
            choices = parsed.get("choices")
            if not isinstance(choices, list) or not choices:
                raise ValueError("OpenAI-compatible output did not contain choices")
            message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
            content = message.get("content") if isinstance(message, dict) else None
            if not isinstance(content, str):
                raise ValueError("OpenAI-compatible output did not contain message content")
            return json.loads(content)
        if self._protocol == "anthropic":
            content = parsed.get("content")
            if not isinstance(content, list) or not content:
                raise ValueError("Anthropic output did not contain content")
            text = content[0].get("text") if isinstance(content[0], dict) else None
            if not isinstance(text, str):
                raise ValueError("Anthropic output did not contain text content")
            return json.loads(text)
        return parsed.get("output", parsed)


class OpenAICompatibleProvider(HttpJSONLLMProvider):
    def __init__(self, configuration: LLMConfiguration) -> None:
        super().__init__(configuration, "openai_compatible")


class AzureOpenAIProvider(HttpJSONLLMProvider):
    def __init__(self, configuration: LLMConfiguration) -> None:
        super().__init__(configuration, "azure_openai")


class AnthropicProvider(HttpJSONLLMProvider):
    def __init__(self, configuration: LLMConfiguration) -> None:
        super().__init__(configuration, "anthropic")


def validate_structured_output(
    request: StructuredLLMRequest, output: dict[str, Any]
) -> dict[str, Any]:
    """Reject missing fields and values outside the caller-owned schema."""
    missing = [field for field in request.required_fields if field not in output]
    if missing:
        raise ValueError(f"LLM output missing required fields: {', '.join(missing)}")
    for field, allowed in request.allowed_values.items():
        if field in output and str(output[field]) not in allowed:
            raise ValueError(f"LLM output field is outside allowed values: {field}")
    return output


def build_llm_provider(configuration: LLMConfiguration) -> LLMProvider:
    """Build a configured provider while keeping provider-specific code isolated."""
    if configuration.provider == "deterministic":
        return DeterministicLLMProvider()
    if configuration.provider in {"http_json", "local_json"}:
        return HttpJSONLLMProvider(configuration)
    if configuration.provider == "openai_compatible":
        return OpenAICompatibleProvider(configuration)
    if configuration.provider == "azure_openai":
        return AzureOpenAIProvider(configuration)
    if configuration.provider == "anthropic":
        return AnthropicProvider(configuration)
    raise LLMProviderError(f"unsupported LLM provider: {configuration.provider}")
