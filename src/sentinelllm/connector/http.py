"""HTTP target connector using the Python standard library."""

import asyncio
import json
from http.cookiejar import CookieJar
from time import monotonic
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener

from sentinelllm.connector.base import TargetConnector, TargetResponse


class _NoRedirectHandler(HTTPRedirectHandler):
    """Expose redirects as responses so policy controls every contacted destination."""

    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


class HttpTargetConnector(TargetConnector):
    """Session-aware HTTP transport with bounded retries and normalized responses."""

    def __init__(
        self,
        timeout_seconds: float = 10.0,
        retries: int = 2,
        default_headers: dict[str, str] | None = None,
        concurrency: int = 1,
        minimum_request_interval_seconds: float = 0.0,
        maximum_requests: int = 50,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._retries = retries
        self._default_headers = default_headers or {}
        self._semaphore = asyncio.Semaphore(concurrency)
        self._pacing_lock = asyncio.Lock()
        self._minimum_request_interval_seconds = minimum_request_interval_seconds
        self._last_request_at = 0.0
        self._maximum_requests = maximum_requests
        self._request_count = 0
        self._request_lock = asyncio.Lock()
        self._opener = build_opener(HTTPCookieProcessor(CookieJar()), _NoRedirectHandler())

    async def send(self, request: dict[str, Any]) -> TargetResponse:
        """Send an already policy-approved request without interpreting its content."""
        async with self._semaphore:
            await self._pace()
            last_error = "request failed"
            for attempt in range(self._retries + 1):
                if not await self._reserve_request():
                    return TargetResponse(
                        None,
                        None,
                        metadata={"error": "connector request budget exhausted"},
                    )
                try:
                    return await asyncio.to_thread(self._send_sync, request, attempt)
                except (OSError, TimeoutError, URLError) as error:
                    last_error = type(error).__name__
            return TargetResponse(
                None, None, metadata={"error": last_error, "retries": self._retries}
            )

    async def _reserve_request(self) -> bool:
        async with self._request_lock:
            if self._request_count >= self._maximum_requests:
                return False
            self._request_count += 1
            return True

    async def _pace(self) -> None:
        if not self._minimum_request_interval_seconds:
            return
        async with self._pacing_lock:
            remaining = self._minimum_request_interval_seconds - (
                monotonic() - self._last_request_at
            )
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._last_request_at = monotonic()

    def _send_sync(self, request: dict[str, Any], attempt: int) -> TargetResponse:
        url = str(request["url"])
        method = str(request.get("method", "GET")).upper()
        headers = {
            **self._default_headers,
            **{str(key): str(value) for key, value in request.get("headers", {}).items()},
        }
        payload = request.get("json", request.get("body"))
        data: bytes | None = None
        if payload is not None:
            if isinstance(payload, (dict, list)):
                data = json.dumps(payload).encode("utf-8")
                headers.setdefault("Content-Type", "application/json")
            else:
                data = str(payload).encode("utf-8")
        prepared = Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(  # noqa: S310
                prepared, timeout=self._timeout_seconds
            ) as response:
                body = response.read().decode("utf-8", errors="replace")
                response_headers = dict(response.headers.items())
                return TargetResponse(
                    response.status,
                    body,
                    response_headers,
                    {
                        "url": response.url,
                        "attempt": attempt,
                        "content_type": response.headers.get_content_type(),
                    },
                )
        except HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            return TargetResponse(
                error.code,
                body,
                dict(error.headers.items()),
                {"url": url, "attempt": attempt, "content_type": error.headers.get_content_type()},
            )
