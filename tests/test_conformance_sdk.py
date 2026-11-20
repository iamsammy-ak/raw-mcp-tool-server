"""Conformance: drive the real server with the official MCP Python SDK *client*.

The SDK is a development dependency only (the server never imports it). It validates every
result against its own protocol models and checks ``structuredContent`` against each tool's
``outputSchema``, so a passing run is independent evidence that the wire format is right.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from rawmcp.policy import hash_token
from rawmcp.server import McpServer

from .conftest import SRC, TOKENS

mcp = pytest.importorskip("mcp", reason="the official MCP SDK (2.x, Python 3.11+) is not installed")
if not hasattr(mcp, "Client"):
    pytest.skip("needs the 2.x SDK client", allow_module_level=True)

from mcp import Client  # noqa: E402
from mcp.client.stdio import StdioServerParameters  # noqa: E402

pytestmark = [pytest.mark.sdk, pytest.mark.subprocess]


@pytest.fixture
def policy_file(tmp_path: Path, workspace: Path) -> Path:
    data = {
        "version": 1,
        "workspace": str(workspace),
        "audit_log": str(tmp_path / "audit.jsonl"),
        "profiles": {
            "reader": {"scopes": ["fs:read", "db:read"], "token_sha256": [hash_token(TOKENS["reader"])]},
            "analyst": {"scopes": ["fs:read", "db:read", "exec:python"]},
        },
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def stdio_params(policy_file: Path, profile: str = "reader", page_size: int = 3) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "rawmcp", "serve", "--policy", str(policy_file), "--profile", profile, "--no-watch",
              "--page-size", str(page_size)],
        env={"PYTHONPATH": SRC},
    )


async def list_all(client: Any) -> list[Any]:
    tools, cursor = [], None
    while True:
        page = await client.list_tools(cursor=cursor)
        tools += page.tools
        cursor = page.next_cursor
        if cursor is None:
            return tools


async def test_sdk_auto_mode_negotiates_2026_07_28(policy_file: Path) -> None:
    async with Client(stdio_params(policy_file), mode="auto") as client:
        assert client.protocol_version == "2026-07-28"
        assert client.server_info is not None and client.server_info.name == "rawmcp"
        tools = await list_all(client)
        assert [t.name for t in tools] == ["calculate", "list_dir", "read_file", "search_files", "sqlite_query"]
        result = await client.call_tool("calculate", {"expression": "2 ** 10"})
        assert result.is_error is False and result.structured_content == {
            "expression": "2 ** 10", "result": 1024, "type": "int"}
        rows = await client.call_tool("sqlite_query", {"sql": "SELECT COUNT(*) AS n FROM customers"})
        assert rows.structured_content["rows"] == [[60]]
        escaped = await client.call_tool("read_file", {"path": "../policy.yaml"})  # tool errors are results
        assert escaped.is_error is True and "outside the workspace" in escaped.content[0].text
        invalid = await client.call_tool("calculate", {"expression": 12})
        assert invalid.is_error is True


async def test_sdk_legacy_handshake(policy_file: Path) -> None:
    async with Client(stdio_params(policy_file), mode="legacy") as client:
        assert client.protocol_version == "2025-11-25"
        tools = await list_all(client)
        assert len(tools) == 5
        result = await client.call_tool("read_file", {"path": "hello.txt"})
        assert result.structured_content["content"] == "hello world\n"
        resources = await client.list_resources()
        assert {str(r.uri) for r in resources.resources} == {"rawmcp://db/schema", "rawmcp://policy/effective"}


async def test_sdk_progress_callback(policy_file: Path, workspace: Path) -> None:
    for i in range(30):
        (workspace / f"n{i}.txt").write_text("needle\n", encoding="utf-8")
    seen: list[float] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        seen.append(progress)

    async with Client(stdio_params(policy_file), mode="auto") as client:
        await list_all(client)
        result = await client.call_tool("search_files", {"query": "needle"}, progress_callback=on_progress)
        assert len(result.structured_content["matches"]) == 30
    assert seen and seen == sorted(seen)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def test_sdk_over_streamable_http(policy_file: Path) -> None:
    httpx2 = pytest.importorskip("httpx2")
    uvicorn = pytest.importorskip("uvicorn")
    from mcp.client.streamable_http import streamable_http_client

    from rawmcp.policy import load_policy
    from rawmcp.transports.http import create_app

    port = _free_port()
    app = create_app(McpServer(load_policy(policy_file)), port=port)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        await asyncio.sleep(0.05)
    try:
        for mode in ("auto", "legacy"):
            http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {TOKENS['reader']}"})
            transport = streamable_http_client(f"http://127.0.0.1:{port}/mcp", http_client=http)
            async with Client(transport, mode=mode) as client:
                expected = "2026-07-28" if mode == "auto" else "2025-11-25"
                assert client.protocol_version == expected
                await list_all(client)
                result = await client.call_tool("calculate", {"expression": "3 * 14"})
                assert result.structured_content["result"] == 42
    finally:
        server.should_exit = True
        thread.join(timeout=10)
