"""Tests for structured, same-origin attack-surface discovery."""

import json

from sentinelllm.discovery.parsers import parse_html_forms, parse_openapi


def test_openapi_parser_extracts_methods_body_parameters_and_content_type() -> None:
    document = json.dumps(
        {
            "openapi": "3.1.0",
            "paths": {
                "/chat": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": {
                                            "prompt": {"type": "string"},
                                            "session": {"type": "string"},
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
        }
    )

    endpoints = parse_openapi("https://example.test/api", document)

    assert len(endpoints) == 1
    assert endpoints[0].url == "https://example.test/chat"
    assert endpoints[0].method == "POST"
    assert endpoints[0].parameters == ("prompt", "session")
    assert endpoints[0].content_types == ("application/json",)


def test_html_parser_extracts_same_origin_forms_only() -> None:
    document = """
    <form action="/chat" method="post"><textarea name="prompt"></textarea></form>
    <form action="https://outside.test/collect" method="post">
      <input name="secret">
    </form>
    """

    endpoints = parse_html_forms("https://example.test", document)

    assert len(endpoints) == 1
    assert endpoints[0].url == "https://example.test/chat"
    assert endpoints[0].method == "POST"
    assert endpoints[0].parameters == ("prompt",)


def test_malformed_or_non_openapi_documents_produce_no_endpoints() -> None:
    assert parse_openapi("https://example.test", "not json") == ()
    assert parse_openapi("https://example.test", '{"paths": []}') == ()
