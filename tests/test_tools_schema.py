"""Tool definitions: Pydantic-generated JSON Schemas, strict validation and per-revision shaping."""

from __future__ import annotations

import json

import jsonschema
import pytest

from rawmcp.versions import REVISIONS

from .conftest import Harness, text_of

SAMPLE_CALLS = {
    "calculate": {"expression": "sqrt(16) + 2**10"},
    "list_dir": {"path": "notes"},
    "read_file": {"path": "hello.txt"},
    "search_files": {"query": "carrier"},
    "sqlite_query": {"sql": "SELECT category, COUNT(*) AS n FROM products GROUP BY category ORDER BY category"},
    "write_file": {"path": "out.txt", "content": "written"},
    "fetch_url": {"url": "https://example.com/"},
    "run_python": {"code": "print(sum(range(10)))"},
}


async def test_every_schema_is_valid_draft_2020_12(harness) -> None:
    h: Harness = harness("maintainer")
    tools = []
    cursor = None
    while True:
        result = (await h.request("tools/list", {"cursor": cursor} if cursor else {}))["result"]
        tools += result["tools"]
        cursor = result.get("nextCursor")
        if cursor is None:
            break
    assert {t["name"] for t in tools} == set(SAMPLE_CALLS)
    for tool in tools:
        for key in ("inputSchema", "outputSchema"):
            schema = tool[key]
            jsonschema.Draft202012Validator.check_schema(schema)
            assert schema["type"] == "object"
        assert tool["inputSchema"]["additionalProperties"] is False
        assert tool["annotations"]["readOnlyHint"] in (True, False)
        assert tool["_meta"]["dev.rawmcp/requiredScopes"] == sorted(tool["_meta"]["dev.rawmcp/requiredScopes"])


@pytest.mark.parametrize("name", sorted(SAMPLE_CALLS))
async def test_structured_content_matches_output_schema(harness, name: str) -> None:
    h: Harness = harness("maintainer")
    definition = next(t for t in h.server.all_tools() if t.name == name)
    response = await h.call(name, SAMPLE_CALLS[name])
    result = response["result"]
    assert result["isError"] is False, text_of(response)
    jsonschema.validate(result["structuredContent"], definition.output_schema(),
                        cls=jsonschema.Draft202012Validator)
    jsonschema.validate(SAMPLE_CALLS[name], definition.input_schema(), cls=jsonschema.Draft202012Validator)
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]  # text mirrors structure


@pytest.mark.parametrize(
    "arguments",
    [
        {"expression": 5},  # strict: no int -> str coercion
        {"expression": "1+1", "extra": True},  # extra="forbid"
        {},  # missing required field
        {"expression": ""},  # min_length
    ],
)
async def test_invalid_arguments_are_tool_errors_on_new_revisions(harness, arguments: dict) -> None:
    h: Harness = harness()
    response = await h.call("calculate", arguments)
    assert response["result"]["isError"] is True  # SEP-1303: the model can read and fix this
    assert text_of(response).startswith("Invalid arguments for calculate")


async def test_invalid_arguments_are_protocol_errors_on_2025_06_18(harness) -> None:
    h: Harness = harness()
    await h.initialize("2025-06-18")
    response = await h.call("calculate", {"expression": 5}, modern=False)
    assert response["error"]["code"] == -32602
    assert response["error"]["data"]["errors"][0]["field"] == "expression"


async def test_strict_int_rejects_string_number(harness) -> None:
    h: Harness = harness()
    response = await h.call("read_file", {"path": "hello.txt", "max_bytes": "10"})
    assert response["result"]["isError"] is True and "max_bytes" in text_of(response)


async def test_unknown_tool_is_a_protocol_error(harness) -> None:
    h: Harness = harness()
    response = await h.call("format_disk", {})
    assert response["error"]["code"] == -32602
    assert "Unknown tool" in response["error"]["message"]


async def test_malformed_call_params_are_protocol_errors(harness) -> None:
    h: Harness = harness()
    assert (await h.request("tools/call", {"arguments": {}}))["error"]["code"] == -32602
    assert (await h.request("tools/call", {"name": "calculate", "arguments": [1]}))["error"]["code"] == -32602


@pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
async def test_tool_shape_follows_the_negotiated_revision(harness, version: str) -> None:
    h: Harness = harness("maintainer")
    await h.initialize(version)
    revision = REVISIONS[version]
    tools = (await h.request("tools/list", modern=False))["result"]["tools"]
    tool = tools[0]
    assert ("outputSchema" in tool) == revision.structured_output
    assert ("title" in tool) == revision.structured_output
    assert ("annotations" in tool) == revision.tool_annotations
    call = (await h.call("calculate", {"expression": "1+2"}, modern=False))["result"]
    assert ("structuredContent" in call) == revision.structured_output
    assert json.loads(call["content"][0]["text"])["result"] == 3


async def test_definitions_are_deterministic(harness) -> None:
    h: Harness = harness("maintainer")
    first = await h.request("tools/list")
    second = await h.request("tools/list")
    assert first["result"]["tools"] == second["result"]["tools"]
