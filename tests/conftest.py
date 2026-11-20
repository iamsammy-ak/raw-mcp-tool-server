"""Shared fixtures: an offline policy, a fake network, and an in-process client harness."""

from __future__ import annotations

import asyncio
import itertools
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import configuration as hypothesis_configuration

from rawmcp.client import server_command  # noqa: F401  (re-exported for the tests)
from rawmcp.context import Principal
from rawmcp.policy import Policy, hash_token, policy_from_dict
from rawmcp.server import Connection, McpServer, ServerOptions
from rawmcp.tools.fetch import FetchResponse

# Keep Hypothesis' example database and caches out of the repository.
hypothesis_configuration.set_hypothesis_home_dir(Path(tempfile.gettempdir()) / "rawmcp-hypothesis")

MODERN = "2026-07-28"
SRC = str(Path(__file__).resolve().parents[1] / "src")
TOKENS = {"reader": "test-reader-token", "analyst": "test-analyst-token", "maintainer": "test-maintainer-token"}


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test may depend on an LLM key or on outbound network access."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("RAWMCP_TOKEN", raising=False)
    monkeypatch.delenv("RAWMCP_POLICY", raising=False)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    (root / "notes").mkdir(parents=True)
    (root / "notes" / "todo.txt").write_bytes(b"buy coffee\ncheck the Carrier contract\n")
    (root / "notes" / "plan.md").write_bytes(b"# Plan\nship the carrier report\n")
    (root / "hello.txt").write_bytes(b"hello world\n")
    (root / "blob.bin").write_bytes(b"\x00\x01\x02binary")
    (tmp_path / "secret.txt").write_text("outside the jail\n", encoding="utf-8")
    return root


def make_policy(tmp_path: Path, workspace: Path, **overrides: Any) -> Policy:
    data: dict[str, Any] = {
        "version": 1,
        "workspace": str(workspace),
        "audit_log": str(tmp_path / "audit.jsonl"),
        "fetch": {"allow_domains": ["example.com", "*.python.org"]},
        "sandbox": {"timeout_s": 5, "max_timeout_s": 10, "max_output_bytes": 4096},
        "profiles": {
            "reader": {"scopes": ["fs:read", "db:read"], "token_sha256": [hash_token(TOKENS["reader"])]},
            "analyst": {"scopes": ["fs:read", "db:read", "exec:python", "net:fetch"],
                        "token_sha256": [hash_token(TOKENS["analyst"])],
                        "rate_limits": {"run_python": "100/minute"}},
            "maintainer": {"scopes": ["fs:read", "fs:write", "db:read", "exec:python", "net:fetch"],
                           "token_sha256": [hash_token(TOKENS["maintainer"])]},
            "limited": {"scopes": ["fs:read"], "rate_limits": {"*": "2/minute"}},
        },
    }
    data.update(overrides)
    return policy_from_dict(data, tmp_path)


@pytest.fixture
def policy(tmp_path: Path, workspace: Path) -> Policy:
    return make_policy(tmp_path, workspace)


class FakeFetcher:
    """Serves canned responses; records requested URLs; follows a scripted redirect map."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.redirects: dict[str, str] = {}
        self.content_type = "text/html; charset=utf-8"
        self.body = b"<html><body>Example Domain</body></html>"

    def fetch(self, url: str, *, timeout: float, max_bytes: int, max_redirects: int,
              check_redirect: Callable[[str], None]) -> FetchResponse:
        self.calls.append(url)
        hops = 0
        while url in self.redirects:
            hops += 1
            url = self.redirects[url]
            check_redirect(url)
        body = self.body
        return FetchResponse(final_url=url, status=200, content_type=self.content_type, body=body[:max_bytes],
                             truncated=len(body) > max_bytes)


def fake_resolver(host: str) -> list[str]:
    table = {"example.com": ["93.184.215.14"], "docs.python.org": ["151.101.0.223"],
             "evil.example.com": ["127.0.0.1"], "metadata.python.org": ["169.254.169.254"]}
    if host not in table:
        raise OSError("unknown host")
    return table[host]


@pytest.fixture
def fetcher() -> FakeFetcher:
    return FakeFetcher()


@pytest.fixture
def server(policy: Policy, fetcher: FakeFetcher) -> McpServer:
    return McpServer(policy, options=ServerOptions(page_size=3), fetcher=fetcher, resolver=fake_resolver)


def modern_meta(**extra: Any) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "pytest", "version": "1"},
    }
    meta.update(extra)
    return meta


class Harness:
    """Drives a :class:`Connection` exactly like the stdio transport does, without a subprocess."""

    def __init__(self, server: McpServer, profile: str | None) -> None:
        self.server = server
        self.outbox: list[Any] = []
        self._waiters: dict[Any, asyncio.Future[dict[str, Any]]] = {}
        self._ids = itertools.count(1)
        self.connection: Connection = server.connect("test", Principal(profile, "test"), self._send)

    async def _send(self, message: Any) -> None:
        json.dumps(message, allow_nan=False)  # everything sent must be strict JSON
        self.outbox.append(message)
        if isinstance(message, dict) and "id" in message and ("result" in message or "error" in message):
            waiter = self._waiters.pop(message["id"], None)
            if waiter is not None and not waiter.done():
                waiter.set_result(message)

    async def raw(self, line: str | bytes) -> None:
        await self.connection.feed(line)
        for _ in range(3):
            await asyncio.sleep(0)

    async def request(self, method: str, params: dict[str, Any] | None = None, *, modern: bool = True,
                      request_id: Any = None, timeout: float = 15.0, **meta_extra: Any) -> dict[str, Any]:
        rid = next(self._ids) if request_id is None else request_id
        body = dict(params or {})
        if modern:
            body["_meta"] = {**modern_meta(**meta_extra), **body.get("_meta", {})}
        elif meta_extra:
            body["_meta"] = {**meta_extra, **body.get("_meta", {})}
        waiter: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._waiters[rid] = waiter
        await self.connection.feed(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": body}))
        return await asyncio.wait_for(waiter, timeout)

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        await self.raw(json.dumps(message))

    async def initialize(self, version: str = "2025-11-25") -> dict[str, Any]:
        response = await self.request("initialize", {"protocolVersion": version, "capabilities": {},
                                                     "clientInfo": {"name": "pytest", "version": "1"}}, modern=False)
        await self.notify("notifications/initialized")
        return response

    async def call(self, tool: str, arguments: dict[str, Any] | None = None, *, modern: bool = True,
                   **meta_extra: Any) -> dict[str, Any]:
        params: dict[str, Any] = {"name": tool}
        if arguments is not None:
            params["arguments"] = arguments
        return await self.request("tools/call", params, modern=modern, **meta_extra)

    def notifications(self, method: str) -> list[dict[str, Any]]:
        return [m for m in self.outbox if isinstance(m, dict) and m.get("method") == method]


@pytest.fixture
def harness(server: McpServer) -> Callable[[str | None], Harness]:
    def make(profile: str | None = "reader") -> Harness:
        return Harness(server, profile)

    return make


def text_of(response: dict[str, Any]) -> str:
    return "\n".join(block["text"] for block in response["result"]["content"] if block["type"] == "text")
