"""Streamable HTTP transport: security checks, header mirroring, sessions and SSE."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from starlette.testclient import TestClient

from rawmcp.server import McpServer
from rawmcp.transports.http import McpHttpApp, decode_header_value

from .conftest import MODERN, TOKENS, modern_meta

BASE = "http://127.0.0.1:8706"
ACCEPT = "application/json, text/event-stream"


@pytest.fixture
def client(server: McpServer) -> TestClient:
    return TestClient(McpHttpApp(server, port=8706).app, base_url=BASE)


def headers(token: str = TOKENS["reader"], **extra: str) -> dict[str, str]:
    base = {"Authorization": f"Bearer {token}", "Accept": ACCEPT, "Content-Type": "application/json"}
    base.update({k.replace("_", "-"): v for k, v in extra.items()})
    return base


def modern_post(client: TestClient, method: str, params: dict[str, Any] | None = None, *, rid: Any = 1,
                token: str = TOKENS["reader"], meta: dict[str, Any] | None = None, **header_overrides: str):
    body_params = dict(params or {})
    body_params["_meta"] = meta if meta is not None else modern_meta()
    hdrs = headers(token, **{"MCP-Protocol-Version": MODERN, "Mcp-Method": method})
    name = body_params.get("name") or body_params.get("uri")
    if name is not None:
        hdrs["Mcp-Name"] = name
    hdrs.update(header_overrides)
    return client.post("/mcp", headers=hdrs,
                       content=json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": body_params}))


def test_get_is_not_offered(client: TestClient) -> None:
    assert client.get("/mcp", headers=headers()).status_code == 405


def test_foreign_host_header_is_forbidden(client: TestClient) -> None:
    response = client.post("/mcp", headers={**headers(), "Host": "attacker.example"}, content="{}")
    assert response.status_code == 403


def test_disallowed_origin_is_forbidden_with_idless_error(client: TestClient) -> None:
    response = modern_post(client, "server/discover", Origin="https://evil.example")
    assert response.status_code == 403
    assert "id" not in response.json() and response.json()["error"]["code"] == -32600
    ok = modern_post(client, "server/discover", Origin="http://localhost:8706")
    assert ok.status_code == 200


@pytest.mark.parametrize("token", [None, "wrong-token"])
def test_missing_or_unknown_token_is_unauthorised(client: TestClient, token: str | None) -> None:
    hdrs = headers()
    if token is None:
        del hdrs["Authorization"]
    else:
        hdrs["Authorization"] = f"Bearer {token}"
    assert client.post("/mcp", headers=hdrs, content="{}").status_code == 401


def test_content_negotiation(client: TestClient) -> None:
    assert client.post("/mcp", headers={**headers(), "Content-Type": "text/plain"}, content="{}").status_code == 415
    assert client.post("/mcp", headers={**headers(), "Accept": "application/json"}, content="{}").status_code == 406


def test_parse_error_is_400(client: TestClient) -> None:
    response = client.post("/mcp", headers=headers(), content="{not json")
    assert response.status_code == 400 and response.json()["error"]["code"] == -32700


def test_modern_call_returns_json_without_session(client: TestClient) -> None:
    response = modern_post(client, "tools/call", {"name": "calculate", "arguments": {"expression": "6*7"}})
    assert response.status_code == 200 and "mcp-session-id" not in response.headers
    assert response.json()["result"]["structuredContent"]["result"] == 42


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"MCP-Protocol-Version": "2025-06-18"}, "MCP-Protocol-Version"),
        ({"Mcp-Method": "tools/list"}, "Mcp-Method"),
        ({"Mcp-Name": "read_file"}, "Mcp-Name"),
    ],
)
def test_header_body_mismatch_is_rejected(client: TestClient, overrides: dict[str, str], fragment: str) -> None:
    response = modern_post(client, "tools/call", {"name": "calculate", "arguments": {"expression": "1"}},
                           **overrides)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32020 and fragment in response.json()["error"]["message"]


def test_missing_protocol_version_header_is_rejected(client: TestClient) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": modern_meta()}}
    response = client.post("/mcp", headers=headers(**{"Mcp-Method": "server/discover"}), content=json.dumps(body))
    assert response.status_code == 400 and response.json()["error"]["code"] == -32020


def test_base64_encoded_mcp_name_is_decoded(client: TestClient) -> None:
    encoded = "=?base64?" + base64.b64encode(b"calculate").decode() + "?="
    assert decode_header_value(encoded) == "calculate"
    response = modern_post(client, "tools/call", {"name": "calculate", "arguments": {"expression": "2"}},
                           **{"Mcp-Name": encoded})
    assert response.status_code == 200


def test_unsupported_version_unknown_method_and_missing_meta(client: TestClient) -> None:
    meta = modern_meta(**{"io.modelcontextprotocol/protocolVersion": "1900-01-01"})
    unsupported = modern_post(client, "tools/list", meta=meta, **{"MCP-Protocol-Version": "1900-01-01"})
    assert unsupported.status_code == 400 and unsupported.json()["error"]["code"] == -32022
    unknown = modern_post(client, "tools/teleport")
    assert unknown.status_code == 404 and unknown.json()["error"]["code"] == -32601
    no_caps = modern_post(client, "tools/list", meta={"io.modelcontextprotocol/protocolVersion": MODERN})
    assert no_caps.status_code == 400 and no_caps.json()["error"]["code"] == -32602


def test_progress_token_switches_to_sse(client: TestClient, workspace) -> None:
    for i in range(40):
        (workspace / f"f{i}.txt").write_text("carrier\n", encoding="utf-8")
    meta = modern_meta(progressToken="tok")
    response = modern_post(client, "tools/call", {"name": "search_files", "arguments": {"query": "carrier"}},
                           meta=meta)
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["x-accel-buffering"] == "no"
    events = [json.loads(line[len("data: "):]) for line in response.text.splitlines() if line.startswith("data: ")]
    assert [e.get("method") for e in events[:-1]] == ["notifications/progress"] * (len(events) - 1)
    assert events[-1]["id"] == 1 and events[-1]["result"]["isError"] is False


def test_client_notifications_are_accepted_with_202(client: TestClient) -> None:
    response = client.post("/mcp", headers=headers(), content='{"jsonrpc":"2.0","method":"notifications/x"}')
    assert response.status_code == 202 and response.content == b""


def _initialize(client: TestClient, version: str = "2025-06-18", token: str = TOKENS["reader"]) -> str:
    body = {"jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
    response = client.post("/mcp", headers=headers(token), content=json.dumps(body))
    assert response.status_code == 200 and response.json()["result"]["protocolVersion"] == version
    return response.headers["mcp-session-id"]


def test_legacy_session_lifecycle(client: TestClient) -> None:
    sid = _initialize(client)
    assert len(sid) == 32 and all(c in "0123456789abcdef" for c in sid)
    initialized = client.post("/mcp", headers=headers(**{"Mcp-Session-Id": sid}),
                              content='{"jsonrpc":"2.0","method":"notifications/initialized"}')
    assert initialized.status_code == 202
    listing = client.post("/mcp", headers=headers(**{"Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-06-18"}),
                          content='{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    assert listing.status_code == 200 and "resultType" not in listing.json()["result"]
    wrong_version = client.post("/mcp", headers=headers(**{"Mcp-Session-Id": sid,
                                                           "MCP-Protocol-Version": "2025-11-25"}),
                                content='{"jsonrpc":"2.0","id":2,"method":"ping"}')
    assert wrong_version.status_code == 400
    assert client.delete("/mcp", headers=headers(**{"Mcp-Session-Id": sid})).status_code == 204
    gone = client.post("/mcp", headers=headers(**{"Mcp-Session-Id": sid}),
                       content='{"jsonrpc":"2.0","id":3,"method":"ping"}')
    assert gone.status_code == 404


def test_legacy_request_without_session_is_400(client: TestClient) -> None:
    response = client.post("/mcp", headers=headers(), content='{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    assert response.status_code == 400 and "Mcp-Session-Id" in response.json()["error"]["message"]


def test_session_cannot_be_used_with_another_token(client: TestClient) -> None:
    sid = _initialize(client, token=TOKENS["reader"])
    hijack = client.post("/mcp", headers=headers(TOKENS["maintainer"], **{"Mcp-Session-Id": sid}),
                         content='{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    assert hijack.status_code == 404


def test_batch_only_for_2025_03_26_sessions(client: TestClient) -> None:
    batch = json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "ping"},
                        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "calculate", "arguments": {"expression": "2+2"}}}])
    old = _initialize(client, "2025-03-26")
    ok = client.post("/mcp", headers=headers(**{"Mcp-Session-Id": old}), content=batch)
    assert ok.status_code == 200 and sorted(r["id"] for r in ok.json()) == [1, 2]
    new = _initialize(client, "2025-06-18")
    rejected = client.post("/mcp", headers=headers(**{"Mcp-Session-Id": new}), content=batch)
    assert rejected.status_code == 400 and rejected.json()["error"]["code"] == -32600
