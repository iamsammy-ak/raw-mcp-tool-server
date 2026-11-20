"""Per-request context objects shared by the server core and the tools."""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from rawmcp.protocol import LOG_LEVELS
from rawmcp.versions import Revision

log = logging.getLogger("rawmcp")

Notify = Callable[[dict[str, Any]], Awaitable[None]]
"""Sends one server-to-client notification on the stream that carries the related response."""


@dataclass(frozen=True)
class Principal:
    """The authenticated caller. Scopes are looked up from the live policy on every call."""

    profile: str | None
    subject: str
    """Where the identity came from, e.g. ``stdio:--profile`` or ``http:token#1a2b3c4d``."""

    @property
    def label(self) -> str:
        return self.profile or "anonymous"


@dataclass
class Inflight:
    """Book-keeping for one running request, so ``notifications/cancelled`` can stop it."""

    task: asyncio.Task[Any] | None = None
    cancel_callbacks: list[Callable[[], None]] = field(default_factory=list)
    cancelled: bool = False

    def cancel(self) -> None:
        """Run the tool's cancel hooks (kill a subprocess, interrupt SQLite) and cancel the task."""
        if self.cancelled:
            return
        self.cancelled = True
        for callback in self.cancel_callbacks:
            try:
                callback()
            except Exception:  # a failing hook must not prevent the task cancellation below
                log.exception("cancel hook failed")
        if self.task is not None and not self.task.done():
            self.task.cancel()


class ToolContext:
    """What a running tool may use: progress, logging and cancellation hooks."""

    def __init__(
        self,
        *,
        principal: Principal,
        revision: Revision,
        notify: Notify,
        progress_token: str | int | None,
        log_threshold: int | None,
        inflight: Inflight,
    ) -> None:
        self.principal = principal
        self.revision = revision
        self._notify = notify
        self._progress_token = progress_token
        self._log_threshold = log_threshold
        self._inflight = inflight
        self._last_progress = float("-inf")
        self.cancelled = threading.Event()
        """Set when the request is cancelled; worker threads poll it."""
        inflight.cancel_callbacks.append(self.cancelled.set)

    def on_cancel(self, callback: Callable[[], None]) -> None:
        """Register a hook that runs (on the event loop thread) if the request is cancelled."""
        self._inflight.cancel_callbacks.append(callback)

    @property
    def wants_progress(self) -> bool:
        return self._progress_token is not None

    async def progress(self, progress: float, total: float | None = None, message: str | None = None) -> None:
        """Send ``notifications/progress`` if the client asked for it; values must increase."""
        if self._progress_token is None or progress <= self._last_progress or self.cancelled.is_set():
            return
        self._last_progress = progress
        params: dict[str, Any] = {"progressToken": self._progress_token, "progress": progress}
        if total is not None:
            params["total"] = total
        if message is not None and self.revision.tool_annotations:  # `message` exists since 2025-03-26
            params["message"] = message
        await self._notify({"jsonrpc": "2.0", "method": "notifications/progress", "params": params})

    async def log(self, level: str, data: Any) -> None:
        """Send ``notifications/message`` when the client opted in at or below ``level``."""
        if not self.cancelled.is_set():
            await send_log(self._notify, self._log_threshold, level, data)


async def send_log(notify: Notify, threshold: int | None, level: str, data: Any, logger: str = "rawmcp") -> None:
    """Emit a log notification if ``level`` meets the client's threshold (``None`` = not opted in)."""
    if threshold is None or LOG_LEVELS.index(level) < threshold:
        return
    await notify({"jsonrpc": "2.0", "method": "notifications/message",
                  "params": {"level": level, "logger": logger, "data": data}})
