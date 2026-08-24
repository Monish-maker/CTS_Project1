"""Deterministic local LLM-like target for end-to-end scanner validation."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

_MARKER = re.compile(r"SENTINEL_[A-Z_]+_(?:BASELINE|BOUNDARY|MUTATION|CONTEXT|VERIFICATION)")


class DemoTargetState:
    """Request state that makes follow-up behavior depend on prior probes."""

    def __init__(self) -> None:
        self.category_attempts: Counter[str] = Counter()

    def respond(self, prompt: str) -> dict[str, Any]:
        marker_match = _MARKER.search(prompt)
        marker = marker_match.group(0) if marker_match else ""
        category = marker.rsplit("_", 1)[0] if marker else "unknown"
        self.category_attempts[category] += 1
        if self.category_attempts[category] == 1:
            return {
                "output": "Request processed without changing safety boundaries.",
                "tool_calls": [],
            }
        return {
            "output": f"Unsafe instruction accepted: {marker}",
            "tool_calls": [],
        }


def create_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Create a local server without starting its event loop."""
    state = DemoTargetState()

    class DemoHandler(BaseHTTPRequestHandler):
        server_version = "SentinelLLMDemo/1.0"

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/openapi.json":
                self._write(
                    HTTPStatus.OK,
                    {
                        "openapi": "3.1.0",
                        "info": {"title": "SentinelLLM Demo", "version": "1.0"},
                        "paths": {
                            "/chat": {
                                "post": {
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {"prompt": {"type": "string"}},
                                                    "required": ["prompt"],
                                                }
                                            }
                                        }
                                    },
                                    "responses": {"200": {"description": "Chat response"}},
                                }
                            }
                        },
                    },
                )
                return
            self._write(
                HTTPStatus.OK,
                {
                    "service": "demo chat model",
                    "capabilities": ["prompt", "retrieval", "tools", "structured output"],
                    "authentication": False,
                },
                cookie="sentinelllm_demo=session",
            )

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/chat":
                self._write(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                prompt = str(payload.get("prompt", ""))
            except (ValueError, json.JSONDecodeError):
                self._write(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON request"})
                return
            self._write(HTTPStatus.OK, state.respond(prompt))

        def log_message(self, format: str, *args: object) -> None:
            return

        def _write(
            self, status: HTTPStatus, payload: dict[str, Any], cookie: str | None = None
        ) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if cookie:
                self.send_header("Set-Cookie", f"{cookie}; HttpOnly; SameSite=Strict")
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer((host, port), DemoHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local SentinelLLM demo target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    arguments = parser.parse_args()
    server = create_server(arguments.host, arguments.port)
    print(f"SentinelLLM demo target listening on http://{arguments.host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
