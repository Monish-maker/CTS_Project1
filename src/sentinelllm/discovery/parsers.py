"""Structured parsers for observable API and HTML attack surfaces."""

from __future__ import annotations

import json
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from sentinelllm.core.models import EndpointProfile

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def parse_openapi(base_url: str, document: str) -> tuple[EndpointProfile, ...]:
    """Parse endpoint methods and parameters from an OpenAPI JSON document."""
    try:
        parsed = json.loads(document)
    except json.JSONDecodeError:
        return ()
    if not isinstance(parsed, dict) or not isinstance(parsed.get("paths"), dict):
        return ()
    endpoints: list[EndpointProfile] = []
    for path, path_item in parsed["paths"].items():
        if not isinstance(path_item, dict):
            continue
        shared_parameters = _parameter_names(path_item.get("parameters", []))
        for method, operation in path_item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            parameters = set(shared_parameters)
            parameters.update(_parameter_names(operation.get("parameters", [])))
            request_body = operation.get("requestBody", {})
            content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
            content_types = (
                tuple(str(item) for item in content) if isinstance(content, dict) else ()
            )
            if isinstance(content, dict):
                for media in content.values():
                    if isinstance(media, dict):
                        schema = media.get("schema", {})
                        if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
                            parameters.update(str(item) for item in schema["properties"])
            endpoint_url = urljoin(base_url, str(path))
            if _same_origin(base_url, endpoint_url):
                endpoints.append(
                    EndpointProfile(
                        endpoint_url,
                        method.upper(),
                        tuple(sorted(parameters)),
                        content_types,
                        "openapi",
                    )
                )
    return tuple(endpoints)


class _FormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "form":
            self._current = {
                "action": attributes.get("action") or self.base_url,
                "method": (attributes.get("method") or "GET").upper(),
                "parameters": [],
            }
        elif tag in {"input", "textarea", "select"} and self._current is not None:
            if attributes.get("name"):
                self._current["parameters"].append(attributes["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def parse_html_forms(base_url: str, document: str) -> tuple[EndpointProfile, ...]:
    """Extract same-origin form methods and named input parameters."""
    parser = _FormParser(base_url)
    parser.feed(document)
    endpoints = []
    for form in parser.forms:
        url = urljoin(base_url, str(form["action"]))
        if _same_origin(base_url, url):
            endpoints.append(
                EndpointProfile(
                    url,
                    str(form["method"]),
                    tuple(str(item) for item in form["parameters"]),
                    ("application/x-www-form-urlencoded",),
                    "html_form",
                )
            )
    return tuple(endpoints)


def _parameter_names(parameters: Any) -> set[str]:
    if not isinstance(parameters, list):
        return set()
    return {str(item["name"]) for item in parameters if isinstance(item, dict) and item.get("name")}


def _same_origin(base_url: str, candidate_url: str) -> bool:
    base = urlparse(base_url)
    candidate = urlparse(candidate_url)
    return candidate.scheme in {"http", "https"} and candidate.netloc == base.netloc
