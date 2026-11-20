"""Version negotiation in both eras: stateless 2026-07-28 and the legacy initialize handshake."""

from __future__ import annotations

import pytest

from rawmcp.versions import LEGACY_VERSIONS, SUPPORTED_VERSIONS

from .conftest import MODERN, Harness


async def test_discover_advertises_versions_capabilities_and_cache_hints(harness) -> None:
    h: Harness = harness()
    result = (await h.request("server/discover"))["result"]
    assert result["resultType"] == "complete"
    assert result["supportedVersions"][0] == MODERN
    assert set(result["supportedVersions"]) == set(SUPPORTED_VERSIONS)
    assert result["capabilities"]["tools"] == {"listChanged": True}
    assert result["cacheScope"] == "public" and result["ttlMs"] > 0
    assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "rawmcp"


async def test_modern_requests_need_no_handshake(harness) -> None:
    h: Harness = harness()
    response = await h.call("calculate", {"expression": "1+1"})
    assert response["result"]["structuredContent"]["result"] == 2


async def test_unknown_modern_version_lists_supported(harness) -> None:
    h: Harness = harness()
    response = await h.request("tools/list", **{"io.modelcontextprotocol/protocolVersion": "1900-01-01"})
    error = response["error"]
    assert error["code"] == -32022
    assert error["data"] == {"supported": list(SUPPORTED_VERSIONS), "requested": "1900-01-01"}


async def test_legacy_version_in_per_request_meta_is_rejected_with_hint(harness) -> None:
    h: Harness = harness()
    response = await h.request("tools/list", **{"io.modelcontextprotocol/protocolVersion": "2025-06-18"})
    assert response["error"]["code"] == -32022
    assert "initialize" in response["error"]["message"]


async def test_missing_client_capabilities_is_invalid_params(harness) -> None:
    h: Harness = harness()
    params = {"_meta": {"io.modelcontextprotocol/protocolVersion": MODERN}}
    response = await h.request("tools/list", params, modern=False)
    assert response["error"]["code"] == -32602
    assert "clientCapabilities" in response["error"]["message"]


async def test_request_without_meta_or_session_is_rejected(harness) -> None:
    h: Harness = harness()
    response = await h.request("tools/list", modern=False)
    assert response["error"]["code"] == -32602
    assert MODERN in response["error"]["data"]["supported"]


@pytest.mark.parametrize("version", LEGACY_VERSIONS)
async def test_initialize_echoes_supported_legacy_versions(harness, version: str) -> None:
    h: Harness = harness()
    result = (await h.initialize(version))["result"]
    assert result["protocolVersion"] == version
    assert "resultType" not in result  # legacy results have no resultType
    assert result["serverInfo"]["name"] == "rawmcp"
    assert ("title" in result["serverInfo"]) == (version >= "2025-06-18")
    assert ("description" in result["serverInfo"]) == (version == "2025-11-25")


@pytest.mark.parametrize("requested", ["2023-01-01", "2026-07-28", "banana"])
async def test_initialize_counter_offers_latest_legacy(harness, requested: str) -> None:
    h: Harness = harness()
    result = (await h.initialize(requested))["result"]
    assert result["protocolVersion"] == "2025-11-25"


async def test_initialize_twice_is_invalid(harness) -> None:
    h: Harness = harness()
    await h.initialize()
    again = await h.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                           "clientInfo": {"name": "x", "version": "1"}}, modern=False)
    assert again["error"]["code"] == -32600


async def test_initialize_with_bad_params_is_invalid_params(harness) -> None:
    h: Harness = harness()
    response = await h.request("initialize", {"protocolVersion": 20250618}, modern=False)
    assert response["error"]["code"] == -32602


async def test_ping_is_legacy_only(harness) -> None:
    h: Harness = harness()
    assert (await h.request("ping", modern=False))["result"] == {}  # allowed before initialize
    assert (await h.request("ping"))["error"]["code"] == -32601  # removed in 2026-07-28
    await h.initialize()
    assert (await h.request("ping", modern=False))["result"] == {}


async def test_logging_set_level_is_legacy_only_and_gates_messages(harness) -> None:
    h: Harness = harness()
    assert (await h.request("logging/setLevel", {"level": "debug"}))["error"]["code"] == -32601
    await h.initialize("2025-06-18")
    await h.call("calculate", {"expression": "2"}, modern=False)
    assert h.notifications("notifications/message") == []  # nothing until the client opts in
    assert (await h.request("logging/setLevel", {"level": "loud"}, modern=False))["error"]["code"] == -32602
    assert (await h.request("logging/setLevel", {"level": "info"}, modern=False))["result"] == {}
    await h.call("calculate", {"expression": "2"}, modern=False)
    levels = [m["params"]["level"] for m in h.notifications("notifications/message")]
    assert levels == ["info"]  # the debug message is below the threshold


async def test_modern_log_level_is_per_request(harness) -> None:
    h: Harness = harness()
    await h.call("calculate", {"expression": "3"})
    assert h.notifications("notifications/message") == []
    await h.call("calculate", {"expression": "3"}, **{"io.modelcontextprotocol/logLevel": "debug"})
    assert [m["params"]["level"] for m in h.notifications("notifications/message")] == ["debug", "info"]
    bad = await h.call("calculate", {"expression": "3"}, **{"io.modelcontextprotocol/logLevel": "verbose"})
    assert bad["error"]["code"] == -32602


async def test_modern_and_legacy_requests_can_share_a_connection(harness) -> None:
    h: Harness = harness()
    await h.initialize("2025-06-18")
    legacy = await h.request("tools/list", modern=False)
    modern = await h.request("tools/list")
    assert "resultType" not in legacy["result"] and modern["result"]["resultType"] == "complete"
    assert "ttlMs" in modern["result"] and "ttlMs" not in legacy["result"]
