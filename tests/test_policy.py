"""Policy file, deny-by-default authorisation, rate limits and the audit log."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rawmcp.audit import hash_arguments
from rawmcp.policy import RateLimit, default_policy, hash_token, load_policy, policy_from_dict
from rawmcp.ratelimit import RateLimiter
from rawmcp.server import McpServer

from .conftest import TOKENS, Harness, make_policy, text_of


def test_example_policy_file_loads_and_resolves_paths() -> None:
    path = Path(__file__).resolve().parents[1] / "examples" / "policy.yaml"
    policy = load_policy(path)
    assert policy.workspace == path.parent / "workspace"
    assert policy.audit_log == path.parent / "audit.jsonl"
    assert policy.authenticate("demo-analyst-token") == "analyst"
    assert policy.authenticate("demo-reader-token") == "reader"
    assert policy.authenticate("wrong") is None
    assert "exec:python" not in policy.profiles["reader"].scopes


def test_default_policy_is_read_only(tmp_path: Path) -> None:
    policy = default_policy(tmp_path)
    profile = policy.profiles[policy.stdio_profile or ""]
    assert profile.scopes == frozenset({"fs:read", "db:read"})


@pytest.mark.parametrize(
    "bad",
    [
        {"profiles": {"p": {"scopes": ["fs:delete"]}}},  # unknown scope
        {"profiles": {"p": {"scopes": [], "surprise": 1}}},  # unknown key
        {"profiles": {"p": {"token_sha256": ["not-a-hash"]}}},
        {"profiles": {"p": {"rate_limits": {"*": "lots"}}}},
        {"stdio_profile": "ghost"},
        {"fetch": {"allow_domains": ["exa mple.com"]}},
        {"version": 2},
    ],
)
def test_invalid_policies_are_rejected(tmp_path: Path, bad: dict) -> None:
    data = {"version": 1, "workspace": str(tmp_path), **bad}
    with pytest.raises(ValidationError):
        policy_from_dict(data, tmp_path)


def test_duplicate_token_hash_is_rejected(tmp_path: Path) -> None:
    digest = hash_token("same")
    with pytest.raises(ValidationError):
        policy_from_dict({"workspace": str(tmp_path), "profiles": {"a": {"token_sha256": [digest]},
                                                                   "b": {"token_sha256": [digest]}}}, tmp_path)


def test_rate_limit_parsing_and_buckets() -> None:
    limit = RateLimit.parse("3/minute")
    assert (limit.calls, limit.period_s, str(limit)) == (3, 60.0, "3/minute")
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0])
    assert [limiter.check("p", "t", limit).allowed for _ in range(4)] == [True, True, True, False]
    denied = limiter.check("p", "t", limit)
    assert denied.retry_after_s == pytest.approx(20.0)
    now[0] = 20.0  # one token refilled after 60/3 seconds
    assert limiter.check("p", "t", limit).allowed
    assert limiter.check("other", "t", limit).allowed  # buckets are per principal
    assert limiter.check("p", "t", None).allowed  # no limit configured


async def test_anonymous_principal_sees_nothing_and_is_denied(harness) -> None:
    h: Harness = harness(None)
    assert (await h.request("tools/list"))["result"]["tools"] == []
    response = await h.call("calculate", {"expression": "1"})
    assert response["result"]["isError"] is True and "deny by default" in text_of(response)


async def test_tools_list_is_filtered_by_scope(harness) -> None:
    async def names(profile: str) -> set[str]:
        h: Harness = harness(profile)
        found: set[str] = set()
        cursor = None
        while True:
            result = (await h.request("tools/list", {"cursor": cursor} if cursor else {}))["result"]
            found |= {t["name"] for t in result["tools"]}
            cursor = result.get("nextCursor")
            if not cursor:
                return found

    reader = await names("reader")
    assert reader == {"calculate", "list_dir", "read_file", "search_files", "sqlite_query"}
    assert "write_file" in await names("maintainer")
    assert {"run_python", "fetch_url"} <= await names("analyst")


async def test_missing_scope_is_denied_and_audited(harness, server: McpServer) -> None:
    h: Harness = harness("reader")
    response = await h.call("write_file", {"path": "x.txt", "content": "nope"})
    assert response["result"]["isError"] is True
    assert "needs scope fs:write" in text_of(response)
    assert not (server.policy.workspace / "x.txt").exists()
    record = server.audit.recent()[-1]
    assert (record.tool, record.decision, record.principal) == ("write_file", "deny", "reader")


async def test_rate_limit_denies_after_burst(harness) -> None:
    h: Harness = harness("limited")
    outcomes = [(await h.call("read_file", {"path": "hello.txt"}))["result"]["isError"] for _ in range(3)]
    assert outcomes == [False, False, True]
    last = await h.call("read_file", {"path": "hello.txt"})
    assert "rate limit exceeded" in text_of(last)


async def test_audit_log_is_jsonl_with_argument_hash_not_arguments(harness, server: McpServer) -> None:
    h: Harness = harness("reader")
    await h.call("read_file", {"path": "hello.txt"})
    await h.call("read_file", {"path": "../secret.txt"})
    await h.call("calculate", {"expression": 7})
    await h.call("nope", {})
    assert server.policy.audit_log is not None
    lines = [json.loads(line) for line in server.policy.audit_log.read_text(encoding="utf-8").splitlines()]
    assert [line["decision"] for line in lines] == ["allow", "deny", "invalid", "unknown_tool"]
    first = lines[0]
    assert first["args_sha256"] == hash_arguments({"path": "hello.txt"})
    assert "hello.txt" not in json.dumps(first)  # arguments are hashed, never stored
    assert first["duration_ms"] >= 0 and first["subject"] == "test" and first["protocol_version"] == "2026-07-28"


def test_argument_hash_is_order_independent() -> None:
    assert hash_arguments({"a": 1, "b": [1, 2]}) == hash_arguments({"b": [1, 2], "a": 1})
    assert hash_arguments({"a": 1}) != hash_arguments({"a": 2})


async def test_policy_reload_changes_scopes_and_announces_it(tmp_path: Path, workspace: Path, harness,
                                                             server: McpServer) -> None:
    h: Harness = harness("reader")
    await h.initialize()
    assert (await h.call("write_file", {"path": "a.txt", "content": "x"}))["result"]["isError"] is True
    upgraded = make_policy(tmp_path, workspace, profiles={
        "reader": {"scopes": ["fs:read", "fs:write"], "token_sha256": [hash_token(TOKENS["reader"])]}})
    await server.update_policy(upgraded)
    assert h.notifications("notifications/tools/list_changed")
    assert (await h.call("write_file", {"path": "a.txt", "content": "x"}))["result"]["isError"] is False
