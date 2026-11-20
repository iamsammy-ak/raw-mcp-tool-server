"""Streamable HTTP transport: one MCP endpoint (``/mcp``) that accepts POST.

Modern (2026-07-28) requests are stateless: the ``MCP-Protocol-Version``, ``Mcp-Method`` and
``Mcp-Name`` headers must mirror the body, no session id is minted, and closing an SSE
response stream cancels the request. Legacy clients (2025-03-26 to 2025-11-25) get the
earlier shape: ``initialize`` returns an ``Mcp-Session-Id`` that later requests must send,
and ``DELETE`` ends the session. Standalone ``GET`` streams are not offered (405), which both
eras permit.

Security checks run before anything is parsed: ``Host`` must be a loopback name (DNS
rebinding defence), a present ``Origin`` must be allowlisted (403 otherwise), and every
request needs ``Authorization: Bearer <token>`` matching a policy profile (401 otherwise).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import secrets
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request as HttpRequest
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from rawmcp.context import Principal
from rawmcp.jsonrpc import (
    HEADER_MISMATCH,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    JsonRpcError,
    Notification,
    Request,
    classify,
    decode,
    encode,
    error_response,
)
from rawmcp.policy import hash_token
from rawmcp.server import MODERN_METHODS, Connection, McpServer, check_modern_meta
from rawmcp.versions import LEGACY_VERSIONS, META_LOG_LEVEL, META_PROTOCOL_VERSION

log = logging.getLogger("rawmcp.http")

MAX_BODY_BYTES = 1_000_000
SESSION_IDLE_S = 30 * 60
MAX_SESSIONS = 256
KEEPALIVE_S = 15.0
NAMED_METHODS = {"tools/call": "name", "resources/read": "uri", "prompts/get": "name"}
_DONE = object()


@dataclass
class _Session:
    connection: Connection
    principal: Principal
    last_used: float


def _rpc_error(status: int, code: int, message: str, request_id: Any = None, data: Any = None) -> JSONResponse:
    return JSONResponse(error_response(request_id, code, message, data), status_code=status)


def decode_header_value(value: str) -> str:
    """Undo the ``=?base64?...?=`` sentinel encoding used for non-ASCII ``Mcp-Name``/``Mcp-Param-*`` values."""
    if value.startswith("=?base64?") and value.endswith("?=") and len(value) >= 11:
        try:
            return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            raise ValueError("malformed base64 header value") from None
    return value


class McpHttpApp:
    """The ASGI application for one :class:`McpServer`."""

    def __init__(self, server: McpServer, *, port: int = 8706, path: str = "/mcp",
                 allowed_origins: list[str] | None = None, allowed_hosts: list[str] | None = None) -> None:
        self.server = server
        self.path = path
        loopback = ["127.0.0.1", "localhost", "[::1]"]
        self.allowed_hosts = set(allowed_hosts or [*loopback, *(f"{h}:{port}" for h in loopback)])
        self.allowed_origins = {f"http://{h}:{port}" for h in loopback} | set(allowed_origins or [])
        self.sessions: dict[str, _Session] = {}
        self.app = Starlette(routes=[Route(path, self.endpoint, methods=["GET", "POST", "DELETE"])])

    # ------------------------------------------------------------------ helpers

    def _guard(self, request: HttpRequest) -> Response | None:
        host = request.headers.get("host", "")
        if host not in self.allowed_hosts:
            return _rpc_error(403, INVALID_REQUEST, "Forbidden: Host header is not allowed")
        origin = request.headers.get("origin")
        if origin is not None and origin not in self.allowed_origins:
            return _rpc_error(403, INVALID_REQUEST, "Forbidden: Origin is not allowed")
        return None

    def _authenticate(self, request: HttpRequest) -> Principal | None:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return None
        token = token.strip()
        profile = self.server.policy.authenticate(token)
        return None if profile is None else Principal(profile, f"http:token#{hash_token(token)[:8]}")

    def _session(self, session_id: str) -> _Session | None:
        now = time.monotonic()
        for sid, sess in list(self.sessions.items()):
            if now - sess.last_used > SESSION_IDLE_S:
                del self.sessions[sid]
                asyncio.ensure_future(sess.connection.close())
        session = self.sessions.get(session_id)
        if session is not None:
            session.last_used = now
        return session

    # ------------------------------------------------------------------ endpoint

    async def endpoint(self, request: HttpRequest) -> Response:
        blocked = self._guard(request)
        if blocked is not None:
            return blocked
        if request.method == "GET":
            return Response(status_code=405, headers={"Allow": "POST, DELETE"})
        principal = self._authenticate(request)
        if principal is None:
            return _rpc_error(401, INVALID_REQUEST, "Unauthorized: send Authorization: Bearer <token>")
        if request.method == "DELETE":
            return await self._delete(request, principal)
        return await self._post(request, principal)

    async def _delete(self, request: HttpRequest, principal: Principal) -> Response:
        session_id = request.headers.get("mcp-session-id")
        if not session_id:
            return Response(status_code=405, headers={"Allow": "POST"})
        session = self._session(session_id)
        if session is None or session.principal != principal:
            return Response(status_code=404)
        del self.sessions[session_id]
        await session.connection.close()
        return Response(status_code=204)

    async def _post(self, request: HttpRequest, principal: Principal) -> Response:
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            return _rpc_error(415, INVALID_REQUEST, "Unsupported Media Type: use Content-Type: application/json")
        accept = request.headers.get("accept", "")
        if "*/*" not in accept and not ("application/json" in accept and "text/event-stream" in accept):
            return _rpc_error(406, INVALID_REQUEST,
                              "Not Acceptable: Accept must list application/json and text/event-stream")
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            return _rpc_error(413, INVALID_REQUEST, f"Payload Too Large: limit is {MAX_BODY_BYTES} bytes")
        try:
            value = decode(body)
        except JsonRpcError as exc:
            return JSONResponse(exc.to_response(), status_code=400)

        session_id = request.headers.get("mcp-session-id")
        if isinstance(value, list):
            session = self._session(session_id) if session_id else None
            if session is None:
                return _rpc_error(400, INVALID_REQUEST, "Invalid Request: JSON-RPC batching is not supported here")
            reply = await session.connection.handle_batch(value, _discard)
            if reply is None:
                return Response(status_code=202)
            return JSONResponse(reply, status_code=400 if isinstance(reply, dict) else 200)
        try:
            message = classify(value)
        except JsonRpcError as exc:
            return JSONResponse(exc.to_response(), status_code=400)
        if not isinstance(message, Request):
            if isinstance(message, Notification) and session_id:
                session = self._session(session_id)
                if session is None:
                    return Response(status_code=404)
                await session.connection.handle_notification(message)
            return Response(status_code=202)

        meta = message.params.get("_meta")
        if message.method == "initialize":
            return await self._initialize(message, principal)
        if isinstance(meta, dict) and META_PROTOCOL_VERSION in meta:
            return await self._modern(request, message, meta, principal)
        return await self._legacy(request, message, principal, session_id)

    # ------------------------------------------------------------------ eras

    async def _initialize(self, message: Request, principal: Principal) -> Response:
        if len(self.sessions) >= MAX_SESSIONS:
            oldest = min(self.sessions, key=lambda sid: self.sessions[sid].last_used)
            await self.sessions.pop(oldest).connection.close()
        connection = self.server.connect("http", principal)
        response = await connection.start(message, _discard)
        if response is None or "error" in response:
            await connection.close()
            return JSONResponse(response, status_code=400)
        session_id = secrets.token_hex(16)
        self.sessions[session_id] = _Session(connection, principal, time.monotonic())
        return JSONResponse(response, headers={"Mcp-Session-Id": session_id})

    async def _modern(self, request: HttpRequest, message: Request, meta: dict[str, Any],
                      principal: Principal) -> Response:
        header_version = request.headers.get("mcp-protocol-version")
        if header_version is None:
            return _rpc_error(400, HEADER_MISMATCH, "Header mismatch: MCP-Protocol-Version header is required",
                              message.id)
        if header_version != meta.get(META_PROTOCOL_VERSION):
            return _rpc_error(400, HEADER_MISMATCH,
                              f"Header mismatch: MCP-Protocol-Version {header_version!r} does not match the body",
                              message.id)
        if request.headers.get("mcp-method") != message.method:
            return _rpc_error(400, HEADER_MISMATCH, "Header mismatch: Mcp-Method header missing or not equal "
                                                    "to the body method", message.id)
        field = NAMED_METHODS.get(message.method)
        if field is not None:
            raw_name = request.headers.get("mcp-name")
            try:
                name = decode_header_value(raw_name) if raw_name is not None else None
            except ValueError:
                name = None
            if name is None or name != message.params.get(field):
                return _rpc_error(400, HEADER_MISMATCH, f"Header mismatch: Mcp-Name header missing or not equal to "
                                                        f"params.{field}", message.id)
        try:
            check_modern_meta(meta)
        except JsonRpcError as exc:
            return JSONResponse(exc.to_response(message.id), status_code=400)
        if message.method not in MODERN_METHODS:
            return _rpc_error(404, METHOD_NOT_FOUND, f"Method not found: {message.method}", message.id)
        connection = self.server.connect("http", principal)
        streaming = (message.method == "subscriptions/listen" or "progressToken" in meta
                     or META_LOG_LEVEL in meta)
        if not streaming:
            try:
                return JSONResponse(await connection.start(message, _discard))
            finally:
                await connection.close()
        return self._stream(connection, message, cancel_on_disconnect=True, close_after=True)

    async def _legacy(self, request: HttpRequest, message: Request, principal: Principal,
                      session_id: str | None) -> Response:
        if not session_id:
            return _rpc_error(400, INVALID_REQUEST,
                              "Bad Request: missing Mcp-Session-Id; call initialize first, or send per-request "
                              f"_meta[{META_PROTOCOL_VERSION!r}]", message.id)
        session = self._session(session_id)
        if session is None or session.principal != principal:
            return _rpc_error(404, INVALID_REQUEST, "Session not found; call initialize again", message.id)
        legacy = session.connection.legacy
        header_version = request.headers.get("mcp-protocol-version")
        if legacy is not None and header_version is not None and header_version != legacy.version:
            detail = "unsupported" if header_version not in LEGACY_VERSIONS else "not the negotiated version"
            return _rpc_error(400, INVALID_REQUEST, f"Bad Request: MCP-Protocol-Version {header_version} is {detail}",
                              message.id)
        if "progressToken" in (message.params.get("_meta") or {}):
            return self._stream(session.connection, message, cancel_on_disconnect=False, close_after=False)
        return JSONResponse(await session.connection.start(message, _discard))

    # ------------------------------------------------------------------ SSE

    def _stream(self, connection: Connection, message: Request, *, cancel_on_disconnect: bool,
                close_after: bool) -> StreamingResponse:
        queue: asyncio.Queue[Any] = asyncio.Queue()

        async def notify(item: dict[str, Any]) -> None:
            await queue.put(item)

        task = connection.start(message, notify)
        task.add_done_callback(lambda _: queue.put_nowait(_DONE))

        async def events() -> AsyncIterator[bytes]:
            finished = False
            try:
                while True:
                    try:
                        item = await asyncio.wait_for(queue.get(), timeout=KEEPALIVE_S)
                    except asyncio.TimeoutError:
                        yield b": keep-alive\n\n"
                        continue
                    if item is _DONE:
                        finished = True
                        response = task.result()
                        if response is not None:
                            yield _sse(response)
                        return
                    yield _sse(item)
            finally:
                if not finished and cancel_on_disconnect:
                    entry = connection.inflight.get(message.id)
                    if entry is not None:
                        entry.cancel()  # closing the response stream is the cancellation signal
                if close_after:
                    asyncio.ensure_future(connection.close())

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _sse(message: Any) -> bytes:
    return b"event: message\ndata: " + encode(message) + b"\n\n"


async def _discard(_: dict[str, Any]) -> None:
    """Notification sink for JSON (non-streaming) responses."""


def create_app(server: McpServer, **kwargs: Any) -> Starlette:
    """Build the Starlette app serving ``server`` at ``/mcp``."""
    return McpHttpApp(server, **kwargs).app


def run_http(server: McpServer, *, host: str = "127.0.0.1", port: int = 8706,
             allowed_origins: list[str] | None = None) -> None:
    """Serve over Streamable HTTP with uvicorn (blocking)."""
    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("binding to %s exposes the server beyond this machine; prefer 127.0.0.1", host)
    allowed_hosts = None if host in ("127.0.0.1", "localhost", "::1") else [host, f"{host}:{port}"]
    app = create_app(server, port=port, allowed_origins=allowed_origins, allowed_hosts=allowed_hosts)
    log.warning("listening on http://%s:%s/mcp", host, port)
    uvicorn.run(app, host=host, port=port, log_level="warning")
