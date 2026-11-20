"""The real stdio process, plus property-based fuzzing of the message handler."""

from __future__ import annotations

import asyncio
import json
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from rawmcp.context import Principal
from rawmcp.server import McpServer
from rawmcp.transports import stdio as stdio_module

from .conftest import make_policy, modern_meta, server_command

# --------------------------------------------------------------------------- real subprocess


@pytest.fixture
def policy_path(tmp_path: Path, workspace: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "workspace": str(workspace),
                                    "profiles": {"reader": {"scopes": ["fs:read", "db:read"]}}}), encoding="utf-8")
    return path


@pytest.mark.subprocess
def test_stdout_carries_only_protocol_messages(policy_path: Path) -> None:
    argv, env = server_command(policy_path, "reader")
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": modern_meta()}}),
        "this is not json",
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "calculate", "arguments": {"expression": "40+2"}, "_meta": modern_meta()}}),
        "",
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "x", "version": "1"}}}),
    ]
    started = time.monotonic()
    proc = subprocess.run(argv, input=("\n".join(lines) + "\n").encode(), capture_output=True, env=env, timeout=60)
    assert proc.returncode == 0
    assert time.monotonic() - started < 30  # exits promptly at end of input
    out = proc.stdout.decode("utf-8").splitlines()
    messages = [json.loads(line) for line in out]  # every stdout line is a JSON-RPC message
    by_id = {m.get("id"): m for m in messages}
    assert by_id[1]["result"]["resultType"] == "complete"
    assert by_id[2]["result"]["structuredContent"]["result"] == 42
    assert by_id[3]["result"]["protocolVersion"] == "2024-11-05"
    assert by_id[None]["error"]["code"] == -32700
    assert len(messages) == 4


async def test_oversized_line_is_rejected_and_stream_continues(server: McpServer, monkeypatch) -> None:
    monkeypatch.setattr(stdio_module, "MAX_LINE_BYTES", 1024)
    import io

    payload = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"' + b"x" * 5000 + b'"}}\n'
    payload += b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    out = io.BytesIO()
    await stdio_module.serve_stdio(server, Principal("reader", "test"), stdin=io.BytesIO(payload), stdout=out)
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    assert replies[0]["error"]["code"] == -32600 and "larger than" in replies[0]["error"]["message"]
    assert replies[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}


# --------------------------------------------------------------------------- property-based fuzzing

json_scalars = st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=20)
json_values = st.recursive(json_scalars, lambda inner: st.lists(inner, max_size=4)
                           | st.dictionaries(st.text(max_size=8), inner, max_size=4), max_leaves=12)
methods = st.sampled_from(["initialize", "ping", "tools/list", "tools/call", "server/discover", "resources/read",
                           "resources/list", "logging/setLevel", "subscriptions/listen", "notifications/cancelled",
                           "notifications/initialized", "x/y"]) | st.text(max_size=12)
ids = st.integers() | st.text(max_size=6) | st.none() | st.booleans() | st.floats(allow_nan=False)
envelopes = st.fixed_dictionaries(
    {"jsonrpc": st.sampled_from(["2.0", "2.0", "1.0", 2]), "method": methods},
    optional={"id": ids, "params": json_values | st.fixed_dictionaries(
        {"name": st.sampled_from(["calculate", "read_file", "list_dir", "sqlite_query", "nope"]),
         "arguments": json_values, "_meta": st.just(modern_meta()) | json_values},
        optional={"cursor": json_values, "uri": json_values, "level": json_values,
                  "protocolVersion": json_values, "requestId": json_values})},
)


def _is_valid_reply(message: Any) -> bool:
    if isinstance(message, list):
        return all(_is_valid_reply(m) for m in message)
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return False
    if "method" in message:
        return "id" not in message
    if "error" in message:
        return isinstance(message["error"].get("code"), int) and isinstance(message["error"].get("message"), str)
    return "result" in message and isinstance(message["result"], dict)


async def _feed_all(server: McpServer, lines: list[bytes]) -> list[Any]:
    outbox: list[Any] = []

    async def send(message: Any) -> None:
        json.dumps(message, allow_nan=False)
        outbox.append(message)

    connection = server.connect("fuzz", Principal("reader", "fuzz"), send)
    for line in lines:
        await connection.feed(line)
    await connection.close(drain_timeout_s=5)
    return outbox


@pytest.fixture
def fuzz_server(tmp_path: Path, workspace: Path) -> McpServer:
    return McpServer(make_policy(tmp_path, workspace, audit_log=None))


@pytest.fixture(scope="module")
def loop() -> Iterator[asyncio.AbstractEventLoop]:
    """One event loop for every example: creating a loop per example dominates the runtime on Windows."""
    event_loop = asyncio.new_event_loop()
    yield event_loop
    event_loop.close()


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.lists(envelopes, min_size=1, max_size=6))
def test_structured_fuzz_never_crashes(fuzz_server: McpServer, loop: asyncio.AbstractEventLoop,
                                       messages: list[dict[str, Any]]) -> None:
    lines = [json.dumps(m).encode() for m in messages]
    replies = loop.run_until_complete(_feed_all(fuzz_server, lines))
    assert all(_is_valid_reply(r) for r in replies)
    assert not any(isinstance(r, dict) and r.get("error", {}).get("code") == -32603 for r in replies)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.lists(st.binary(max_size=64) | json_values.map(lambda v: json.dumps(v).encode()), min_size=1, max_size=5))
def test_byte_fuzz_never_crashes(fuzz_server: McpServer, loop: asyncio.AbstractEventLoop, lines: list[bytes]) -> None:
    replies = loop.run_until_complete(_feed_all(fuzz_server, lines))
    assert all(_is_valid_reply(r) for r in replies)


@settings(max_examples=200, deadline=None)
@given(st.lists(st.binary(max_size=40).map(lambda b: b.replace(b"\n", b"")), max_size=8), st.data())
def test_chunked_reader_reassembles_lines_at_any_boundary(lines: list[bytes], data: st.DataObject) -> None:
    stream = b"".join(line + b"\n" for line in lines)
    cuts = sorted(data.draw(st.lists(st.integers(0, len(stream)), max_size=6)))
    pending, state, got = bytearray(), {"discarding": False}, []
    for start, end in zip([0, *cuts], [*cuts, len(stream)], strict=True):
        got += stdio_module.split_lines(stream[start:end], pending, state)
    assert got == [line + b"\n" for line in lines] and not pending


def test_chunked_reader_flags_oversized_lines_split_across_chunks(monkeypatch) -> None:
    monkeypatch.setattr(stdio_module, "MAX_LINE_BYTES", 10)
    pending, state = bytearray(), {"discarding": False}
    got = stdio_module.split_lines(b"x" * 8, pending, state) + stdio_module.split_lines(b"y" * 8, pending, state)
    got += stdio_module.split_lines(b"zz\nok\n", pending, state)
    assert got == [stdio_module._OVERSIZED, b"ok\n"]
