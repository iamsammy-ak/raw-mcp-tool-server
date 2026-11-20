"""A minimal raw JSON-RPC client for the stdio transport (used by the demo, benchmarks and examples).

It speaks newline-delimited JSON to a ``rawmcp serve`` subprocess and keeps a transcript, so the
exact bytes on the wire can be shown. It is intentionally tiny and is not an MCP SDK.
"""

from __future__ import annotations

import itertools
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path
from types import TracebackType
from typing import Any

from rawmcp.versions import LATEST_VERSION, META_CLIENT_CAPABILITIES, META_CLIENT_INFO, META_PROTOCOL_VERSION


def modern_meta(version: str = LATEST_VERSION, **extra: Any) -> dict[str, Any]:
    """The per-request ``_meta`` envelope required by modern revisions."""
    meta: dict[str, Any] = {
        META_PROTOCOL_VERSION: version,
        META_CLIENT_INFO: {"name": "rawmcp-raw-client", "version": "0.1.0"},
        META_CLIENT_CAPABILITIES: {},
    }
    meta.update(extra)
    return meta


def server_command(policy: Path | None, profile: str | None, *extra: str) -> tuple[list[str], dict[str, str]]:
    """argv and environment to launch ``python -m rawmcp serve`` with this package on ``PYTHONPATH``."""
    package_parent = str(Path(__file__).resolve().parents[1])
    env = {**os.environ, "PYTHONPATH": package_parent + os.pathsep + os.environ.get("PYTHONPATH", "")}
    argv = [sys.executable, "-m", "rawmcp", "serve", "--no-watch", *extra]
    if policy is not None:
        argv += ["--policy", str(policy)]
    if profile is not None:
        argv += ["--profile", profile]
    return argv, env


class RawStdioClient:
    """Spawns the server and exchanges raw JSON-RPC lines with it."""

    def __init__(self, argv: list[str], env: dict[str, str] | None = None, cwd: str | None = None) -> None:
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, env=env, cwd=cwd)
        self._inbox: queue.Queue[Any] = queue.Queue()
        self._ids = itertools.count(1)
        self.transcript: list[tuple[str, Any]] = []
        self.stdout_lines: list[bytes] = []
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.stdout_lines.append(line)
            try:
                self._inbox.put(json.loads(line))
            except ValueError:
                self._inbox.put({"_unparseable": line.decode("utf-8", "replace")})
        self._inbox.put(None)

    def send_raw(self, data: bytes) -> None:
        """Write bytes followed by a newline, exactly as given."""
        assert self.proc.stdin is not None
        self.proc.stdin.write(data + b"\n")
        self.proc.stdin.flush()

    def send(self, message: Any) -> None:
        self.transcript.append(("client", message))
        self.send_raw(json.dumps(message, separators=(",", ":")).encode("utf-8"))

    def recv(self, timeout: float = 30.0) -> Any:
        message = self._inbox.get(timeout=timeout)
        if message is None:
            raise EOFError("server closed stdout")
        self.transcript.append(("server", message))
        return message

    def next_id(self) -> int:
        return next(self._ids)

    def request(self, method: str, params: dict[str, Any] | None = None, *, modern: bool = True,
                timeout: float = 30.0, **meta_extra: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Send a request; return its response and the notifications that arrived before it."""
        rid = self.next_id()
        body = dict(params or {})
        if modern:
            body["_meta"] = {**modern_meta(**meta_extra), **body.get("_meta", {})}
        elif meta_extra:
            body["_meta"] = dict(meta_extra)
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": body})
        return self.wait_for(rid, timeout)

    def wait_for(self, rid: Any, timeout: float = 30.0) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        notes: list[dict[str, Any]] = []
        while True:
            message = self.recv(timeout)
            if isinstance(message, dict) and message.get("id") == rid and "method" not in message:
                return message, notes
            notes.append(message)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)

    def close(self, timeout: float = 15.0) -> int:
        """Close stdin (the shutdown signal) and wait for the process to exit."""
        if self.proc.stdin is not None and not self.proc.stdin.closed:
            self.proc.stdin.close()
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.wait()

    def __enter__(self) -> RawStdioClient:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.close()
