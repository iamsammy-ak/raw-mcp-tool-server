"""Append-only JSONL audit log of every ``tools/call``.

Each line records who called which tool, a SHA-256 hash of the arguments (never the
arguments themselves, which may contain file contents or code), the policy decision,
whether the result was an error, and how long the call took.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

Decision = Literal["allow", "deny", "invalid", "unknown_tool", "error", "cancelled"]


class AuditRecord(BaseModel):
    """One audit line."""

    model_config = ConfigDict(extra="forbid")

    ts: str
    transport: str
    protocol_version: str
    principal: str
    subject: str
    request_id: str | int | None
    tool: str
    args_sha256: str
    decision: Decision
    reason: str | None = None
    is_error: bool
    duration_ms: float


def hash_arguments(arguments: Any) -> str:
    """Stable SHA-256 of the arguments' canonical JSON form (sorted keys, no whitespace)."""
    try:
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                               allow_nan=False, default=repr)
    except ValueError:
        canonical = repr(arguments)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def utc_now() -> str:
    """ISO-8601 UTC timestamp with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    """Writes audit records to a JSONL file (if configured) and keeps the most recent ones in memory."""

    def __init__(self, path: Path | None, keep: int = 200) -> None:
        self.path = path
        self._recent: deque[AuditRecord] = deque(maxlen=keep)
        self._lock = threading.Lock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: AuditRecord) -> None:
        """Append one record; each line is flushed immediately so a crash loses nothing already decided."""
        line = record.model_dump_json() + "\n"
        with self._lock:
            self._recent.append(record)
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line)

    def recent(self) -> list[AuditRecord]:
        """The most recent records, oldest first."""
        with self._lock:
            return list(self._recent)
