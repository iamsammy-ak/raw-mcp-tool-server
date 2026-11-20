"""JSON-RPC 2.0 framing: parse errors, invalid requests, id handling, notifications, batches."""

from __future__ import annotations

import json

import pytest

from rawmcp import jsonrpc
from rawmcp.jsonrpc import JsonRpcError, Notification, Request, Response, classify, decode

from .conftest import Harness


@pytest.mark.parametrize("raw", [b"{", b"not json", b"\xff\xfe", b'{"a": NaN}', b"[" * 100 + b"]" * 100])
def test_decode_rejects_bad_input_as_parse_error(raw: bytes) -> None:
    with pytest.raises(JsonRpcError) as info:
        decode(raw)
    assert info.value.code == jsonrpc.PARSE_ERROR
    assert "id" not in info.value.to_response()


@pytest.mark.parametrize(
    ("message", "expected_id"),
    [
        ({"id": 1, "method": "ping"}, 1),  # missing jsonrpc
        ({"jsonrpc": "1.0", "id": "a", "method": "ping"}, "a"),
        ({"jsonrpc": "2.0", "id": 2, "method": 5}, 2),
        ({"jsonrpc": "2.0", "id": 3, "method": "ping", "params": [1, 2]}, 3),
        ({"jsonrpc": "2.0", "id": 4, "method": "ping", "params": None}, 4),
        ({"jsonrpc": "2.0", "id": None, "method": "ping"}, None),
        ({"jsonrpc": "2.0", "id": 1.5, "method": "ping"}, None),
        ({"jsonrpc": "2.0", "id": True, "method": "ping"}, None),
        ({"jsonrpc": "2.0", "id": {"x": 1}, "method": "ping"}, None),
        ({"jsonrpc": "2.0", "id": 5, "method": "ping", "result": {}}, 5),
        ({"jsonrpc": "2.0"}, None),
        ([1], None),
        ("string", None),
    ],
)
def test_classify_invalid_requests(message: object, expected_id: object) -> None:
    with pytest.raises(JsonRpcError) as info:
        classify(message)
    assert info.value.code == jsonrpc.INVALID_REQUEST
    response = info.value.to_response()
    assert response.get("id") == expected_id
    if expected_id is None:
        assert "id" not in response  # MCP: omit the id when it cannot be read


def test_classify_valid_shapes() -> None:
    assert classify({"jsonrpc": "2.0", "id": "x", "method": "m"}) == Request("x", "m", {})
    assert classify({"jsonrpc": "2.0", "method": "n", "params": {"a": 1}}) == Notification("n", {"a": 1})
    assert isinstance(classify({"jsonrpc": "2.0", "id": 1, "result": {}}), Response)


def test_encode_is_one_line_and_strict_json() -> None:
    line = jsonrpc.encode({"jsonrpc": "2.0", "id": 1, "result": {"text": "a\nb c"}})
    assert b"\n" not in line
    assert json.loads(line)["result"]["text"] == "a\nb c"
    with pytest.raises(ValueError):
        jsonrpc.encode({"x": float("nan")})


async def test_parse_error_over_connection(harness) -> None:
    h: Harness = harness()
    await h.raw('{"jsonrpc":"2.0","id":7,"method":')
    assert h.outbox[-1]["error"]["code"] == -32700
    assert "id" not in h.outbox[-1]


async def test_notifications_never_get_a_reply(harness) -> None:
    h: Harness = harness()
    await h.notify("notifications/unknown_thing", {"x": 1})
    await h.notify("tools/list")  # a method without an id is a notification, even a request method
    await h.raw('{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":[1]}}')
    assert h.outbox == []


async def test_unknown_method_is_method_not_found(harness) -> None:
    h: Harness = harness()
    response = await h.request("tools/teleport")
    assert response["error"]["code"] == -32601


async def test_string_and_integer_ids_are_echoed_exactly(harness) -> None:
    h: Harness = harness()
    for rid in ("abc", 0, -5, 2**40, "1"):
        response = await h.request("tools/list", request_id=rid)
        assert response["id"] == rid and type(response["id"]) is type(rid)


async def test_client_responses_are_ignored(harness) -> None:
    h: Harness = harness()
    await h.raw('{"jsonrpc":"2.0","id":99,"result":{}}')
    await h.raw('{"jsonrpc":"2.0","id":98,"error":{"code":1,"message":"x"}}')
    assert h.outbox == []


@pytest.mark.parametrize("version", ["2026-07-28", "2025-11-25", "2025-06-18", "2024-11-05"])
async def test_batches_rejected_unless_revision_allows(harness, version: str) -> None:
    h: Harness = harness()
    if version != "2026-07-28":
        await h.initialize(version)
    await h.raw('[{"jsonrpc":"2.0","id":1,"method":"ping"}]')
    reply = h.outbox[-1]
    assert reply["error"]["code"] == -32600 and "batch" in reply["error"]["message"].lower()


async def test_batch_accepted_for_2025_03_26(harness) -> None:
    h: Harness = harness()
    await h.initialize("2025-03-26")
    batch = [
        {"jsonrpc": "2.0", "id": "a", "method": "ping"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": "b", "method": "tools/call",
         "params": {"name": "calculate", "arguments": {"expression": "6*7"}}},
        {"jsonrpc": "2.0", "id": "c", "method": "initialize", "params": {}},
        {"bogus": True},
    ]
    await h.raw(json.dumps(batch))
    for _ in range(50):
        if isinstance(h.outbox[-1], list):
            break
        await __import__("asyncio").sleep(0.01)
    replies = h.outbox[-1]
    assert isinstance(replies, list)
    by_id = {r.get("id"): r for r in replies}
    assert by_id["a"]["result"] == {}
    assert json.loads(by_id["b"]["result"]["content"][0]["text"])["result"] == 42
    assert by_id["c"]["error"]["code"] == -32600
    assert by_id[None]["error"]["code"] == -32600
    assert len(replies) == 4  # the notification produced no reply


async def test_empty_batch_is_invalid(harness) -> None:
    h: Harness = harness()
    await h.raw("[]")
    assert h.outbox[-1]["error"]["code"] == -32600


async def test_duplicate_in_flight_id_is_rejected(harness) -> None:
    h: Harness = harness("analyst")
    slow = {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "run_python", "arguments": {"code": "import time; time.sleep(3)"},
                       "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                 "io.modelcontextprotocol/clientCapabilities": {}}}}
    await h.raw(json.dumps(slow))
    response = await h.request("tools/list", request_id=5)
    assert response["error"]["code"] == -32600
    await h.notify("notifications/cancelled", {"requestId": 5})
    await h.connection.close()
