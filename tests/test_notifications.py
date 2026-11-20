"""Cancellation, list-changed notifications, subscriptions and pagination."""

from __future__ import annotations

import asyncio
import json

import pytest

from rawmcp.server import McpServer

from .conftest import Harness, modern_meta


async def _wait_for(predicate, timeout: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.01)


@pytest.mark.subprocess
async def test_cancelled_request_gets_no_response_and_stops_work(harness, server: McpServer) -> None:
    h: Harness = harness("analyst")
    code = "import time\nfor i in range(100):\n    print(i, flush=True)\n    time.sleep(0.1)"
    await h.raw(json.dumps({"jsonrpc": "2.0", "id": "slow", "method": "tools/call",
                            "params": {"name": "run_python", "arguments": {"code": code, "timeout_s": 10},
                                       "_meta": modern_meta()}}))
    await _wait_for(lambda: "slow" in h.connection.inflight)
    await asyncio.sleep(0.8)
    started = asyncio.get_running_loop().time()
    await h.notify("notifications/cancelled", {"requestId": "slow", "reason": "user pressed stop"})
    await _wait_for(lambda: "slow" not in h.connection.inflight)
    assert asyncio.get_running_loop().time() - started < 3  # did not run to its 10 s timeout
    await asyncio.sleep(0.2)
    assert not [m for m in h.outbox if m.get("id") == "slow"]  # MUST NOT reply to a cancelled request
    assert server.audit.recent()[-1].decision == "cancelled"
    follow_up = await h.call("calculate", {"expression": "1+1"})
    assert follow_up["result"]["isError"] is False  # the connection keeps working


async def test_cancel_for_unknown_or_finished_request_is_ignored(harness) -> None:
    h: Harness = harness()
    done = await h.call("calculate", {"expression": "2"})
    await h.notify("notifications/cancelled", {"requestId": done["id"]})
    await h.notify("notifications/cancelled", {"requestId": "never-sent"})
    assert len(h.outbox) == 1


async def test_cancelling_a_sqlite_query_interrupts_it(harness) -> None:
    h: Harness = harness()
    sql = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT COUNT(*) FROM c"
    await h.raw(json.dumps({"jsonrpc": "2.0", "id": 77, "method": "tools/call",
                            "params": {"name": "sqlite_query", "arguments": {"sql": sql}, "_meta": modern_meta()}}))
    await asyncio.sleep(0.2)
    await h.notify("notifications/cancelled", {"requestId": 77})
    await _wait_for(lambda: 77 not in h.connection.inflight, timeout=3)
    assert not [m for m in h.outbox if m.get("id") == 77]


async def test_legacy_session_receives_tools_list_changed(harness, server: McpServer) -> None:
    h: Harness = harness()
    await h.initialize("2025-06-18")
    before = {t["name"] for t in (await h.request("tools/list", modern=False))["result"]["tools"]}
    await server.set_tool_enabled("calculate", False)
    assert len(h.notifications("notifications/tools/list_changed")) == 1
    after = await h.request("tools/list", modern=False)
    assert "calculate" in before and "calculate" not in {t["name"] for t in after["result"]["tools"]}
    disabled = await h.call("calculate", {"expression": "1"}, modern=False)
    assert disabled["error"]["code"] == -32602
    await server.set_tool_enabled("calculate", False)  # no change, no notification
    assert len(h.notifications("notifications/tools/list_changed")) == 1


async def test_uninitialized_legacy_session_gets_no_list_changed(harness, server: McpServer) -> None:
    h: Harness = harness()
    await h.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                   "clientInfo": {"name": "x", "version": "1"}}, modern=False)
    await server.set_tool_enabled("calculate", False)
    assert h.notifications("notifications/tools/list_changed") == []


async def test_modern_subscription_ack_notify_and_graceful_close(harness, server: McpServer) -> None:
    h: Harness = harness()
    await h.raw(json.dumps({"jsonrpc": "2.0", "id": "sub-1", "method": "subscriptions/listen",
                            "params": {"_meta": modern_meta(),
                                       "notifications": {"toolsListChanged": True, "promptsListChanged": True}}}))
    await _wait_for(lambda: bool(h.notifications("notifications/subscriptions/acknowledged")))
    ack = h.notifications("notifications/subscriptions/acknowledged")[0]["params"]
    assert ack["_meta"]["io.modelcontextprotocol/subscriptionId"] == "sub-1"
    assert ack["notifications"] == {"toolsListChanged": True}  # unsupported types are omitted
    await server.set_tool_enabled("read_file", False)
    changed = h.notifications("notifications/tools/list_changed")
    assert changed[0]["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"] == "sub-1"
    await h.connection.close()
    final = [m for m in h.outbox if m.get("id") == "sub-1"]
    assert final and final[0]["result"]["_meta"]["io.modelcontextprotocol/subscriptionId"] == "sub-1"


async def test_subscription_cancelled_by_client_ends_without_response(harness, server: McpServer) -> None:
    h: Harness = harness()
    await h.raw(json.dumps({"jsonrpc": "2.0", "id": 5, "method": "subscriptions/listen",
                            "params": {"_meta": modern_meta(), "notifications": {"toolsListChanged": True}}}))
    await _wait_for(lambda: 5 in h.connection.subscriptions)
    await h.notify("notifications/cancelled", {"requestId": 5})
    await _wait_for(lambda: 5 not in h.connection.subscriptions)
    await server.set_tool_enabled("calculate", False)
    assert h.notifications("notifications/tools/list_changed") == []
    assert not [m for m in h.outbox if m.get("id") == 5]


async def test_listen_requires_a_filter_and_is_modern_only(harness) -> None:
    h: Harness = harness()
    assert (await h.request("subscriptions/listen"))["error"]["code"] == -32602
    await h.initialize()
    legacy = await h.request("subscriptions/listen", {"notifications": {}}, modern=False)
    assert legacy["error"]["code"] == -32601


async def test_pagination_walks_every_tool_once(harness) -> None:
    h: Harness = harness("maintainer")  # page_size=3 in the fixture, 8 visible tools
    pages, cursor = [], None
    while True:
        result = (await h.request("tools/list", {"cursor": cursor} if cursor is not None else {}))["result"]
        pages.append([t["name"] for t in result["tools"]])
        cursor = result.get("nextCursor")
        if cursor is None:
            break
    assert [len(p) for p in pages] == [3, 3, 2]
    names = [n for page in pages for n in page]
    assert names == sorted(names) and len(set(names)) == 8


@pytest.mark.parametrize("cursor", ["", "garbage", "eyJvIjogMH0", "eyJvIjo5OTksImYiOiJ4In0", "!!!"])
async def test_invalid_cursor_is_invalid_params(harness, cursor: str) -> None:
    h: Harness = harness("maintainer")
    assert (await h.request("tools/list", {"cursor": cursor}))["error"]["code"] == -32602


async def test_cursor_goes_stale_when_the_list_changes(harness, server: McpServer) -> None:
    h: Harness = harness("maintainer")
    cursor = (await h.request("tools/list"))["result"]["nextCursor"]
    await server.set_tool_enabled("write_file", False)
    stale = await h.request("tools/list", {"cursor": cursor})
    assert stale["error"]["code"] == -32602 and "stale" in stale["error"]["message"]
