"""stdio transport: one JSON-RPC message per line on stdin/stdout.

* stdout carries protocol messages only. ``sys.stdout`` is redirected to stderr while serving,
  so a stray ``print`` anywhere in the process cannot corrupt the stream; logs go to stderr.
* stdin is read on a background thread (portable across Windows and POSIX pipes) and handed to
  the event loop; each request then runs as its own task, so a slow tool never blocks
  ``notifications/cancelled`` or other requests.
* Lines longer than ``MAX_LINE_BYTES`` are discarded with an ``Invalid Request`` error.
* End of input is the shutdown signal: subscriptions end gracefully, in-flight requests are
  cancelled and the function returns.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
from typing import Any, BinaryIO

from rawmcp.context import Principal
from rawmcp.jsonrpc import INVALID_REQUEST, encode, error_response
from rawmcp.server import McpServer

log = logging.getLogger("rawmcp.stdio")

MAX_LINE_BYTES = 4 * 1024 * 1024
DRAIN_TIMEOUT_S = 5.0
"""On end of input, requests already running get this long to finish before they are cancelled."""
_OVERSIZED = object()


def split_lines(chunk: bytes, pending: bytearray, state: dict[str, bool]) -> list[Any]:
    """Split ``chunk`` into complete lines, carrying a partial line over in ``pending``.

    Lines longer than ``MAX_LINE_BYTES`` become the ``_OVERSIZED`` marker and the rest of such a
    line is skipped up to its newline (``state["discarding"]``).
    """
    lines: list[Any] = []
    start = 0
    while (newline := chunk.find(b"\n", start)) >= 0:
        piece = chunk[start:newline + 1]
        start = newline + 1
        if state["discarding"]:
            state["discarding"] = False
            continue
        line = bytes(pending) + piece
        pending.clear()
        lines.append(_OVERSIZED if len(line) > MAX_LINE_BYTES + 1 else line)
    if not state["discarding"]:
        pending += chunk[start:]
        if len(pending) > MAX_LINE_BYTES:
            pending.clear()
            state["discarding"] = True
            lines.append(_OVERSIZED)
    return lines


def _reader(stream: BinaryIO, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue[Any]) -> None:
    """Blocking reader on a daemon thread.

    It reads whatever is available (up to 64 KiB) and hands the event loop all complete lines
    at once. One wake-up per chunk instead of one per line matters when a client pipelines
    requests: every hand-off between this thread and the loop thread is a GIL transfer.
    """
    read = getattr(stream, "read1", stream.read)
    pending = bytearray()
    state = {"discarding": False}
    try:
        while chunk := read(65_536):
            lines = split_lines(chunk, pending, state)
            if lines:
                loop.call_soon_threadsafe(queue.put_nowait, lines)
        if pending and not state["discarding"]:
            loop.call_soon_threadsafe(queue.put_nowait, [bytes(pending)])  # final line without a newline
    except (OSError, ValueError) as exc:
        log.debug("stdin closed: %s", exc)
    finally:
        try:
            loop.call_soon_threadsafe(queue.put_nowait, None)
        except RuntimeError:  # the loop is already closed
            pass


async def serve_stdio(
    server: McpServer,
    principal: Principal,
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
) -> None:
    """Serve one client over binary stdin/stdout until end of input."""
    in_stream = stdin if stdin is not None else sys.stdin.buffer
    out_stream = stdout if stdout is not None else sys.stdout.buffer
    redirected = stdout is None
    if redirected:
        sys.stdout = sys.stderr  # protocol channel stays clean even if something calls print()

    write_lock = threading.Lock()

    async def send(message: Any) -> None:
        data = encode(message) + b"\n"
        with write_lock:
            out_stream.write(data)
            out_stream.flush()

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[Any] = asyncio.Queue()
    threading.Thread(target=_reader, args=(in_stream, loop, queue), name="rawmcp-stdin", daemon=True).start()
    connection = server.connect("stdio", principal, send)
    log.info("serving MCP over stdio as profile %r", principal.label)
    try:
        while (batch := await queue.get()) is not None:
            for line in batch:
                if line is _OVERSIZED:
                    await send(error_response(None, INVALID_REQUEST,
                                              f"Invalid Request: message larger than {MAX_LINE_BYTES} bytes"))
                elif line.strip():
                    await connection.feed(line)
    finally:
        await connection.close(drain_timeout_s=DRAIN_TIMEOUT_S)
        if redirected:
            sys.stdout = sys.__stdout__
        log.info("stdin closed; shutting down")
