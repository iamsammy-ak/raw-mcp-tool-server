"""sqlite_query, fetch_url and calculate."""

from __future__ import annotations

from pathlib import Path

import pytest

from rawmcp.policy import FetchPolicy
from rawmcp.sampledb import build_sample_db, content_digest
from rawmcp.tools.base import ToolError
from rawmcp.tools.calculate import evaluate
from rawmcp.tools.fetch import FetchUrl, host_allowed, is_public_address
from rawmcp.tools.sqlite import bundled_database

from .conftest import FakeFetcher, Harness, fake_resolver, text_of

# --------------------------------------------------------------------------- sqlite_query


def test_bundled_database_is_reproducible(tmp_path: Path) -> None:
    rebuilt = tmp_path / "sample.db"
    build_sample_db(rebuilt)
    assert content_digest(rebuilt) == content_digest(bundled_database())


async def test_sqlite_select_with_params(harness) -> None:
    h: Harness = harness()
    response = await h.call("sqlite_query", {"sql": "SELECT name, unit_price FROM products WHERE category = ? "
                                                     "ORDER BY unit_price DESC", "params": ["kitchen"], "max_rows": 2})
    result = response["result"]["structuredContent"]
    assert result["columns"] == ["name", "unit_price"]
    assert result["row_count"] == 2 and result["truncated"] is True


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM orders",
        "UPDATE products SET unit_price = 0",
        "DROP TABLE customers",
        "INSERT INTO customers VALUES (999, 'x', 'y', 'retail', '2026-01-01')",
        "ATTACH DATABASE 'other.db' AS other",
        "PRAGMA query_only = OFF",
        "CREATE TABLE t (x)",
        "SELECT load_extension('evil')",
    ],
)
async def test_sqlite_is_read_only(harness, sql: str) -> None:
    h: Harness = harness()
    response = await h.call("sqlite_query", {"sql": sql})
    assert response["result"]["isError"] is True
    assert h.server.audit.recent()[-1].decision in ("deny", "error")


async def test_sqlite_rejects_multiple_statements_and_reports_sql_errors(harness) -> None:
    h: Harness = harness()
    multi = await h.call("sqlite_query", {"sql": "SELECT 1; DELETE FROM orders"})
    assert multi["result"]["isError"] is True
    typo = await h.call("sqlite_query", {"sql": "SELEC 1"})
    assert typo["result"]["isError"] is True and "SQL error" in text_of(typo)
    count = await h.call("sqlite_query", {"sql": "SELECT COUNT(*) FROM orders"})
    assert count["result"]["structuredContent"]["rows"] == [[500]]  # nothing was deleted


async def test_sqlite_runaway_query_hits_time_limit(harness) -> None:
    h: Harness = harness()
    sql = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT COUNT(*) FROM c"
    response = await h.call("sqlite_query", {"sql": sql})
    assert response["result"]["isError"] is True and "time limit" in text_of(response)


async def test_db_schema_resource(harness) -> None:
    h: Harness = harness()
    listed = (await h.request("resources/list"))["result"]["resources"]
    assert {r["uri"] for r in listed} == {"rawmcp://db/schema", "rawmcp://policy/effective"}
    read = (await h.request("resources/read", {"uri": "rawmcp://db/schema"}))["result"]
    assert "CREATE TABLE orders" in read["contents"][0]["text"] and read["cacheScope"] == "private"
    policy = (await h.request("resources/read", {"uri": "rawmcp://policy/effective"}))["result"]
    assert '"write_file": "needs fs:write"' in policy["contents"][0]["text"]


async def test_resource_not_found_code_depends_on_revision(harness) -> None:
    modern: Harness = harness()
    assert (await modern.request("resources/read", {"uri": "rawmcp://nope"}))["error"]["code"] == -32602
    legacy: Harness = harness()
    await legacy.initialize("2025-11-25")
    assert (await legacy.request("resources/read", {"uri": "rawmcp://nope"}, modern=False))["error"]["code"] == -32002
    hidden: Harness = harness("limited")  # no db:read scope: the schema resource does not exist for it
    assert (await hidden.request("resources/read", {"uri": "rawmcp://db/schema"}))["error"]["code"] == -32602


# --------------------------------------------------------------------------- fetch_url


@pytest.mark.parametrize(
    ("host", "port", "allowed"),
    [("example.com", None, True), ("www.example.com", None, False), ("docs.python.org", None, True),
     ("python.org", None, False), ("evilpython.org", None, False), ("example.com", 8443, False)],
)
def test_host_allowlist(host: str, port: int | None, allowed: bool) -> None:
    assert host_allowed(host, port, ("example.com", "*.python.org")) is allowed


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "fd00::1",
                                     "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1", "100.64.0.1"])
def test_non_public_addresses(address: str) -> None:
    assert not is_public_address(address)


def test_public_address() -> None:
    assert is_public_address("93.184.215.14") and is_public_address("2606:4700::6810:85e5")


@pytest.mark.parametrize(
    ("url", "fragment"),
    [
        ("http://example.com/", "scheme"),
        ("file:///etc/passwd", "scheme"),
        ("https://user:pw@example.com/", "credentials"),
        ("https://attacker.net/", "allowlist"),
        ("https://example.com:8443/", "allowlist"),
        ("https://127.0.0.1/", "allowlist"),
        ("https://evil.example.com/", "allowlist"),
    ],
)
def test_check_url_denials(url: str, fragment: str) -> None:
    tool = FetchUrl(FetchPolicy(allow_domains=("example.com",)), FakeFetcher(), fake_resolver)
    with pytest.raises(ToolError, match=fragment):
        tool.check_url(url)


def test_allowlisted_name_resolving_to_private_address_is_denied() -> None:
    tool = FetchUrl(FetchPolicy(allow_domains=("*.example.com", "*.python.org")), FakeFetcher(), fake_resolver)
    with pytest.raises(ToolError, match="non-public"):
        tool.check_url("https://evil.example.com/")
    with pytest.raises(ToolError, match="non-public"):
        tool.check_url("https://metadata.python.org/latest")


async def test_fetch_success_and_redirect_recheck(harness, fetcher: FakeFetcher) -> None:
    h: Harness = harness("analyst")
    ok = (await h.call("fetch_url", {"url": "https://example.com/"}))["result"]["structuredContent"]
    assert ok["status"] == 200 and "Example Domain" in ok["text"] and ok["content_type"] == "text/html"
    fetcher.redirects["https://example.com/go"] = "https://attacker.net/steal"
    redirected = await h.call("fetch_url", {"url": "https://example.com/go"})
    assert redirected["result"]["isError"] is True and "allowlist" in text_of(redirected)


async def test_fetch_refuses_binary_and_caps_size(harness, fetcher: FakeFetcher) -> None:
    h: Harness = harness("analyst")
    fetcher.body = b"x" * 5000
    capped = (await h.call("fetch_url", {"url": "https://example.com/", "max_bytes": 100}))["result"]
    assert capped["structuredContent"]["bytes"] == 100 and capped["structuredContent"]["truncated"] is True
    fetcher.content_type = "application/octet-stream"
    binary = await h.call("fetch_url", {"url": "https://example.com/"})
    assert binary["result"]["isError"] is True and "not text" in text_of(binary)


async def test_fetch_needs_net_scope(harness, fetcher: FakeFetcher) -> None:
    h: Harness = harness("reader")
    response = await h.call("fetch_url", {"url": "https://example.com/"})
    assert response["result"]["isError"] is True and fetcher.calls == []


# --------------------------------------------------------------------------- calculate


@pytest.mark.parametrize(
    ("expression", "expected"),
    [("2 * (3 + 4) ** 2", 98), ("7 // 2", 3), ("-2 ** 2", -4), ("10 % 4", 2), ("2 ** -1", 0.5),
     ("round(pi, 3)", 3.142), ("hypot(3, 4)", 5.0), ("max(1, 9, 4)", 9), ("factorial(10)", 3628800)],
)
def test_calculate_values(expression: str, expected: float) -> None:
    assert evaluate(expression) == pytest.approx(expected)


@pytest.mark.parametrize(
    "expression",
    ["__import__('os').system('echo hi')", "(1).__class__", "[1, 2]", "'a' * 3", "lambda: 1", "x", "True + 1",
     "open('f')", "9 ** 9 ** 9", "2 ** 100000", "1 / 0", "sqrt(-1)", "10 ** 400 * 10 ** 4000", "1e308 * 10",
     "factorial(10000)", "", "1 +", "max(*[1])", "round(x=1)"],
)
def test_calculate_rejects_everything_else(expression: str) -> None:
    with pytest.raises(ToolError):
        evaluate(expression)
