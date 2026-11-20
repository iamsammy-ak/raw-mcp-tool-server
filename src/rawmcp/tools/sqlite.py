"""Read-only SQL over a SQLite database.

Four independent layers keep the database read-only and the server responsive:

1. the file is opened with ``mode=ro`` (and ``immutable=1`` for the bundled sample);
2. ``PRAGMA query_only = ON``;
3. an authorizer callback allows only reads (``SELECT``, column reads, functions, recursive
   CTEs) and denies everything else, including ``ATTACH``, ``PRAGMA`` and every write;
4. a progress handler aborts statements that exceed a time budget or are cancelled.
"""

from __future__ import annotations

import asyncio
import math
import sqlite3
import time
from importlib import resources
from pathlib import Path
from typing import Any

from pydantic import Field

from rawmcp.context import ToolContext
from rawmcp.tools.base import PolicyDenied, Tool, ToolError, ToolInput, ToolOutput

QUERY_TIMEOUT_S = 2.0
MAX_ROWS = 500
MAX_VALUE_CHARS = 2_000

_ALLOWED_ACTIONS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
    getattr(sqlite3, "SQLITE_RECURSIVE", 33),
}
_DENIED_FUNCTIONS = {"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer"}


def bundled_database() -> Path:
    """Path of the synthetic sample database shipped with the package."""
    return Path(str(resources.files("rawmcp").joinpath("data/sample.db")))


Scalar = int | float | str | None


class SqliteQueryInput(ToolInput):
    sql: str = Field(min_length=1, max_length=5_000, description="One SELECT statement (CTEs allowed).")
    params: list[Scalar] = Field(default_factory=list, max_length=50,
                                 description="Positional values for ? placeholders.")
    max_rows: int = Field(default=100, ge=1, le=MAX_ROWS)


class SqliteQueryOutput(ToolOutput):
    columns: list[str]
    rows: list[list[Scalar]]
    row_count: int
    truncated: bool
    elapsed_ms: float


def _authorizer(action: int, arg1: str | None, arg2: str | None, db: str | None, trigger: str | None) -> int:
    if action not in _ALLOWED_ACTIONS:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in _DENIED_FUNCTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _scalar(value: Any) -> Scalar:
    if isinstance(value, bytes):
        return f"<blob {len(value)} bytes>"
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
        return value[:MAX_VALUE_CHARS] + "…"
    return value  # type: ignore[no-any-return]


class SqliteQuery(Tool):
    name = "sqlite_query"
    title = "Query SQLite (read-only)"
    description = (
        "Run one read-only SELECT against the configured SQLite database (by default a synthetic "
        "retail sample with tables customers, products, orders, order_items). Writes, ATTACH and "
        "PRAGMA are rejected; queries are limited to 2 seconds."
    )
    input_model = SqliteQueryInput
    output_model = SqliteQueryOutput
    scopes = frozenset({"db:read"})

    def __init__(self, database: Path | None) -> None:
        self.database = database or bundled_database()
        self.immutable = database is None

    def _connect(self) -> sqlite3.Connection:
        if not self.database.is_file():
            raise ToolError("the configured database file does not exist")
        uri = self.database.resolve().as_uri() + ("?mode=ro&immutable=1" if self.immutable else "?mode=ro")
        conn = sqlite3.connect(uri, uri=True)
        conn.execute("PRAGMA query_only = ON")
        if hasattr(conn, "setlimit"):  # Python 3.11+: cap string/blob size and SQL length
            conn.setlimit(getattr(sqlite3, "SQLITE_LIMIT_LENGTH"), 1_000_000)  # noqa: B009
            conn.setlimit(getattr(sqlite3, "SQLITE_LIMIT_ATTACHED"), 0)  # noqa: B009
        conn.set_authorizer(_authorizer)
        return conn

    def schema_sql(self) -> str:
        """The ``CREATE`` statements of every table and index, for the ``rawmcp://db/schema`` resource."""
        conn = self._connect()
        try:
            rows = conn.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type DESC, name")
            return ";\n\n".join(row[0] for row in rows) + ";\n"
        finally:
            conn.close()

    async def run(self, args: SqliteQueryInput, ctx: ToolContext) -> SqliteQueryOutput:
        return await asyncio.to_thread(self._query, args, ctx)

    def _query(self, args: SqliteQueryInput, ctx: ToolContext) -> SqliteQueryOutput:
        started = time.perf_counter()
        deadline = started + QUERY_TIMEOUT_S
        conn = self._connect()
        conn.set_progress_handler(lambda: int(ctx.cancelled.is_set() or time.perf_counter() > deadline), 1_000)
        try:
            cursor = conn.execute(args.sql, args.params)
            columns = [d[0] for d in cursor.description or ()]
            if not columns:
                raise PolicyDenied("only statements that return rows (SELECT) are allowed")
            raw = cursor.fetchmany(args.max_rows + 1)
        except (sqlite3.Error, sqlite3.Warning) as exc:  # Python < 3.12 reports multiple statements as a Warning
            text = str(exc)
            if "not authorized" in text or "readonly" in text or "query_only" in text:
                raise PolicyDenied(f"the database is read-only for this tool: {text}") from None
            if "interrupted" in text:
                raise ToolError(f"query exceeded the {QUERY_TIMEOUT_S:g} s time limit or was cancelled") from None
            raise ToolError(f"SQL error: {text}") from None
        finally:
            conn.close()
        truncated = len(raw) > args.max_rows
        rows = [[_scalar(v) for v in row] for row in raw[: args.max_rows]]
        return SqliteQueryOutput(columns=columns, rows=rows, row_count=len(rows), truncated=truncated,
                                 elapsed_ms=round((time.perf_counter() - started) * 1000, 3))
