"""Transport-independent MCP server core.

:class:`McpServer` owns the tools, the policy, the audit log and the rate limiter.
:class:`Connection` is one client channel (a stdio process, one legacy HTTP session, or one
modern HTTP request) and implements the protocol: era detection, method routing, the legacy
``initialize`` handshake, cancellation, progress, logging, pagination and subscriptions.
Transports only move bytes; they never interpret MCP methods.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from rawmcp import __version__
from rawmcp.audit import AuditLog, AuditRecord, Decision, hash_arguments, utc_now
from rawmcp.context import Inflight, Notify, Principal, ToolContext, send_log
from rawmcp.jail import JailError
from rawmcp.jsonrpc import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    UNSUPPORTED_PROTOCOL_VERSION,
    JsonRpcError,
    Notification,
    Request,
    RequestId,
    classify,
    decode,
    error_response,
    notification,
    result_response,
)
from rawmcp.policy import Policy, Profile
from rawmcp.protocol import (
    LOG_LEVELS,
    CallToolParams,
    CancelledParams,
    Implementation,
    InitializeParams,
    ListenParams,
    PaginatedParams,
    ReadResourceParams,
    SetLevelParams,
    compact_errors,
    parse_params,
)
from rawmcp.ratelimit import RateLimiter
from rawmcp.tools import Tool, ToolError, build_tools
from rawmcp.tools.fetch import Fetcher, Resolver
from rawmcp.tools.sqlite import SqliteQuery
from rawmcp.versions import (
    META_CLIENT_CAPABILITIES,
    META_CLIENT_INFO,
    META_LOG_LEVEL,
    META_PROTOCOL_VERSION,
    META_SERVER_INFO,
    META_SUBSCRIPTION_ID,
    MODERN_VERSIONS,
    REVISIONS,
    SUPPORTED_VERSIONS,
    Revision,
    negotiate_legacy,
)

log = logging.getLogger("rawmcp")

Send = Callable[[Any], Awaitable[None]]
"""Writes one message (or a batch reply) to the client's long-lived channel."""

SERVER_NAME = "rawmcp"
SERVER_TITLE = "Raw MCP Tool Server"
SERVER_DESCRIPTION = "MCP tool server built on raw JSON-RPC, with scoped permissions and a sandbox."
INSTRUCTIONS = (
    "Tools run under a permission policy: tools/list shows only the tools your profile may call. "
    "File paths are relative to the workspace root. A result with isError=true explains what was "
    "refused or failed; fix the arguments rather than retrying unchanged."
)


@dataclass(frozen=True)
class ServerOptions:
    """Tunables that are not part of the security policy."""

    page_size: int = 50
    list_ttl_ms: int = 60_000
    discover_ttl_ms: int = 300_000
    resource_ttl_ms: int = 30_000


@dataclass(frozen=True)
class ResourceSpec:
    """A static resource exposed through ``resources/list`` and ``resources/read``."""

    uri: str
    name: str
    title: str
    description: str
    mime_type: str
    scopes: frozenset[str] = frozenset()


RESOURCES: tuple[ResourceSpec, ...] = (
    ResourceSpec("rawmcp://db/schema", "database-schema", "Database schema",
                 "CREATE statements of the SQLite database behind sqlite_query.", "application/sql",
                 frozenset({"db:read"})),
    ResourceSpec("rawmcp://policy/effective", "effective-policy", "Effective policy",
                 "Your profile, scopes and rate limits, and which tools you may call.", "application/json"),
)


class McpServer:
    """Holds tools, policy and shared services; hands out :class:`Connection` objects."""

    def __init__(
        self,
        policy: Policy,
        *,
        options: ServerOptions | None = None,
        tools: list[Tool] | None = None,
        fetcher: Fetcher | None = None,
        resolver: Resolver | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy
        self.options = options or ServerOptions()
        self._fetcher = fetcher
        self._resolver = resolver
        self._tools: dict[str, Tool] = {}
        self._set_tools(tools if tools is not None else build_tools(policy, fetcher=fetcher, resolver=resolver))
        self._disabled: set[str] = set()
        self.audit = AuditLog(policy.audit_log)
        self.limiter = RateLimiter(clock)
        self.connections: set[Connection] = set()

    # ------------------------------------------------------------------ tools and policy

    def _set_tools(self, tools: list[Tool]) -> None:
        self._tools = {tool.name: tool for tool in sorted(tools, key=lambda t: t.name)}

    def all_tools(self) -> list[Tool]:
        """Every registered tool, enabled or not, sorted by name."""
        return list(self._tools.values())

    def tool(self, name: str) -> Tool | None:
        """An enabled tool by name."""
        return None if name in self._disabled else self._tools.get(name)

    def profile_of(self, principal: Principal) -> Profile | None:
        """The caller's live profile, or ``None`` (no access at all)."""
        return self.policy.profile(principal.profile)

    def visible_tools(self, principal: Principal) -> list[Tool]:
        """Enabled tools whose scopes the caller holds, in a stable order (sorted by name)."""
        profile = self.profile_of(principal)
        if profile is None:
            return []
        return [t for name, t in self._tools.items() if name not in self._disabled and t.scopes <= profile.scopes]

    async def set_tool_enabled(self, name: str, enabled: bool) -> None:
        """Enable or disable a tool at runtime and tell subscribed clients the list changed."""
        if name not in self._tools:
            raise KeyError(name)
        before = set(self._disabled)
        (self._disabled.discard if enabled else self._disabled.add)(name)
        if self._disabled != before:
            await self.notify_tools_changed()

    async def update_policy(self, policy: Policy) -> None:
        """Swap in a new policy (e.g. after the YAML file changed) and announce the new tool list."""
        self.policy = policy
        self._set_tools(build_tools(policy, fetcher=self._fetcher, resolver=self._resolver))
        self.audit = AuditLog(policy.audit_log)
        await self.notify_tools_changed()

    async def notify_tools_changed(self) -> None:
        """Send ``notifications/tools/list_changed`` to every interested client."""
        for connection in list(self.connections):
            await connection.tools_changed()

    # ------------------------------------------------------------------ identity

    def server_info(self, revision: Revision) -> dict[str, Any]:
        info: dict[str, Any] = {"name": SERVER_NAME}
        if revision.structured_output:
            info["title"] = SERVER_TITLE
        info["version"] = __version__
        if revision.icons_and_descriptions:
            info["description"] = SERVER_DESCRIPTION
        return info

    @staticmethod
    def capabilities() -> dict[str, Any]:
        return {"logging": {}, "resources": {}, "tools": {"listChanged": True}}

    def connect(self, transport: str, principal: Principal, send: Send | None = None) -> Connection:
        """Open a connection. ``send`` delivers messages that are not replies (may be ``None`` on HTTP)."""
        connection = Connection(self, transport, principal, send)
        self.connections.add(connection)
        return connection


@dataclass
class LegacySession:
    """State negotiated by ``initialize`` (legacy revisions only)."""

    version: str
    client_info: dict[str, Any]
    client_capabilities: dict[str, Any]
    initialized: bool = False
    log_threshold: int | None = None

    @property
    def revision(self) -> Revision:
        return REVISIONS[self.version]


@dataclass
class Call:
    """Everything a method handler needs about the request it is serving."""

    request: Request
    revision: Revision
    principal: Principal
    notify: Notify
    inflight: Inflight
    log_threshold: int | None
    progress_token: str | int | None

    async def log(self, level: str, data: Any) -> None:
        if not self.inflight.cancelled:
            await send_log(self.notify, self.log_threshold, level, data)


@dataclass
class Subscription:
    """An open ``subscriptions/listen`` stream (2026-07-28)."""

    id: RequestId
    tools_list_changed: bool
    notify: Notify
    done: asyncio.Event = field(default_factory=asyncio.Event)


Handler = Callable[["Connection", Call], Awaitable[dict[str, Any]]]


class Connection:
    """One client channel. Requests on it run concurrently as separate tasks."""

    def __init__(self, server: McpServer, transport: str, principal: Principal, send: Send | None) -> None:
        self.server = server
        self.transport = transport
        self.principal = principal
        self._send = send
        self.legacy: LegacySession | None = None
        self.inflight: dict[RequestId, Inflight] = {}
        self.subscriptions: dict[RequestId, Subscription] = {}
        self._tasks: set[asyncio.Task[Any]] = set()
        self.closed = False

    # ------------------------------------------------------------------ entry points

    async def feed(self, raw: bytes | str) -> None:
        """Process one wire message from a stream transport (stdio). Replies go through ``send``."""
        try:
            value = decode(raw.strip())
        except JsonRpcError as exc:
            await self._emit(exc.to_response())
            return
        if isinstance(value, list):
            self._track(asyncio.ensure_future(self._batch_and_reply(value)))
            return
        try:
            message = classify(value)
        except JsonRpcError as exc:
            await self._emit(exc.to_response())
            return
        if isinstance(message, Request):
            self.start(message, self._emit, reply=self._emit)
        elif isinstance(message, Notification):
            await self.handle_notification(message)
        else:
            log.debug("ignoring a JSON-RPC response from the client (this server sends no requests)")

    def start(
        self,
        request: Request,
        notify: Notify,
        *,
        principal: Principal | None = None,
        reply: Send | None = None,
    ) -> asyncio.Task[dict[str, Any] | None]:
        """Run ``request`` in its own task; the task returns the response (``None`` if cancelled)."""
        who = principal or self.principal
        if request.id in self.inflight:
            duplicate = error_response(request.id, INVALID_REQUEST,
                                       "Invalid Request: id is already in use by a request in progress")
            return self._track(asyncio.ensure_future(self._deliver(duplicate, reply)))
        entry = Inflight()
        self.inflight[request.id] = entry
        task = self._track(asyncio.ensure_future(self._execute(request, notify, who, entry, reply)))
        entry.task = task

        def forget(_: asyncio.Task[Any]) -> None:
            if self.inflight.get(request.id) is entry:
                del self.inflight[request.id]

        task.add_done_callback(forget)
        return task

    async def handle_notification(self, message: Notification) -> None:
        """Process a client notification. Notifications never get a reply, even when malformed."""
        if message.method == "notifications/initialized":
            if self.legacy is not None:
                self.legacy.initialized = True
        elif message.method == "notifications/cancelled":
            try:
                params = CancelledParams.model_validate(message.params)
            except ValidationError:
                return  # malformed cancellations are ignored, as the spec asks
            entry = self.inflight.get(params.requestId)
            if entry is not None:
                log.info("request %r cancelled by client: %s", params.requestId, params.reason or "no reason")
                entry.cancel()
        else:
            log.debug("ignoring notification %s", message.method)

    async def handle_batch(self, items: list[Any], notify: Notify) -> list[dict[str, Any]] | dict[str, Any] | None:
        """Process a JSON-RPC batch. Only a 2025-03-26 legacy session may send one."""
        if not items:
            return error_response(None, INVALID_REQUEST, "Invalid Request: empty batch")
        revision = self.legacy.revision if self.legacy is not None else None
        if revision is None or not revision.batching:
            version = revision.version if revision else "in use"
            return error_response(None, INVALID_REQUEST,
                                  f"Invalid Request: JSON-RPC batching is not supported by protocol revision {version}")
        replies: list[dict[str, Any]] = []
        tasks: list[asyncio.Task[dict[str, Any] | None]] = []
        for item in items:
            try:
                message = classify(item)
            except JsonRpcError as exc:
                replies.append(exc.to_response())
                continue
            if isinstance(message, Request):
                if message.method == "initialize":
                    replies.append(error_response(message.id, INVALID_REQUEST,
                                                  "Invalid Request: initialize must not be part of a batch"))
                else:
                    tasks.append(self.start(message, notify))
            elif isinstance(message, Notification):
                await self.handle_notification(message)
        for result in await asyncio.gather(*tasks):
            if result is not None:
                replies.append(result)
        return replies or None

    async def close(self, drain_timeout_s: float = 0.0) -> None:
        """End subscriptions gracefully, let in-flight requests finish for up to ``drain_timeout_s``,
        cancel whatever is still running, and detach from the server."""
        if self.closed:
            return
        self.closed = True
        listeners = [entry.task for rid, entry in self.inflight.items() if rid in self.subscriptions and entry.task]
        for subscription in list(self.subscriptions.values()):
            subscription.done.set()  # the listen handler returns its completion result
        if listeners:
            await asyncio.wait(listeners, timeout=1.0)
        if self._tasks and drain_timeout_s > 0:
            await asyncio.wait(list(self._tasks), timeout=drain_timeout_s)
        for entry in list(self.inflight.values()):
            entry.cancel()
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
        self.server.connections.discard(self)

    async def tools_changed(self) -> None:
        """Deliver ``notifications/tools/list_changed`` to legacy sessions and opted-in subscriptions."""
        if self.legacy is not None and self.legacy.initialized and self._send is not None:
            await self._emit(notification("notifications/tools/list_changed"))
        for subscription in list(self.subscriptions.values()):
            if subscription.tools_list_changed:
                await subscription.notify(notification("notifications/tools/list_changed",
                                                       {"_meta": {META_SUBSCRIPTION_ID: subscription.id}}))

    # ------------------------------------------------------------------ plumbing

    def _track(self, task: asyncio.Future[Any]) -> asyncio.Task[Any]:
        self._tasks.add(task)  # type: ignore[arg-type]
        task.add_done_callback(self._tasks.discard)
        return task  # type: ignore[return-value]

    async def _emit(self, message: Any) -> None:
        if self._send is not None:
            try:
                await self._send(message)
            except (BrokenPipeError, ConnectionError, OSError, RuntimeError) as exc:
                log.debug("could not deliver a message: %s", exc)

    async def _deliver(self, response: dict[str, Any], reply: Send | None) -> dict[str, Any]:
        if reply is not None:
            await reply(response)
        return response

    async def _batch_and_reply(self, items: list[Any]) -> None:
        reply = await self.handle_batch(items, self._emit)
        if reply is not None:
            await self._emit(reply)

    async def _execute(self, request: Request, notify: Notify, principal: Principal, entry: Inflight,
                       reply: Send | None) -> dict[str, Any] | None:
        try:
            response = result_response(request.id, await self._route(request, notify, principal, entry))
        except JsonRpcError as exc:
            response = exc.to_response(request.id)
        except asyncio.CancelledError:
            return None  # cancelled requests never get a response
        except Exception:
            log.exception("unhandled error while serving %s", request.method)
            response = error_response(request.id, INTERNAL_ERROR, "Internal error")
        if entry.cancelled:
            return None
        return await self._deliver(response, reply)

    # ------------------------------------------------------------------ routing

    async def _route(self, request: Request, notify: Notify, principal: Principal, entry: Inflight) -> dict[str, Any]:
        params = request.params
        meta = params.get("_meta")
        if meta is not None and not isinstance(meta, dict):
            raise JsonRpcError(INVALID_PARAMS, "Invalid params: _meta must be an object")
        if request.method == "initialize":
            return self._initialize(request)
        if meta is not None and META_PROTOCOL_VERSION in meta:
            call = self._modern_call(request, meta, notify, principal, entry)
            handler = MODERN_METHODS.get(request.method)
        elif self.legacy is not None:
            call = self._legacy_call(request, meta or {}, notify, principal, entry)
            handler = LEGACY_METHODS.get(request.method)
        elif request.method == "ping":
            return {}  # legacy clients may ping before initialize
        else:
            raise JsonRpcError(
                INVALID_PARAMS,
                f"Invalid params: missing params._meta[{META_PROTOCOL_VERSION!r}]. Send it on every request "
                f"(protocol {MODERN_VERSIONS[0]}) or call initialize first (2025-11-25 and earlier).",
                {"supported": list(SUPPORTED_VERSIONS)},
            )
        if handler is None:
            raise JsonRpcError(METHOD_NOT_FOUND, f"Method not found: {request.method}",
                               {"protocolVersion": call.revision.version})
        result = await handler(self, call)
        if not call.revision.modern:
            return result
        result_meta = {**result.pop("_meta", {}), META_SERVER_INFO: self.server.server_info(call.revision)}
        return {"resultType": "complete", **result, "_meta": result_meta}

    def _modern_call(self, request: Request, meta: dict[str, Any], notify: Notify, principal: Principal,
                     entry: Inflight) -> Call:
        revision, threshold = check_modern_meta(meta)
        return Call(request, revision, principal, notify, entry, threshold, _progress_token(meta))

    def _legacy_call(self, request: Request, meta: dict[str, Any], notify: Notify, principal: Principal,
                     entry: Inflight) -> Call:
        assert self.legacy is not None
        return Call(request, self.legacy.revision, principal, notify, entry, self.legacy.log_threshold,
                    _progress_token(meta))

    # ------------------------------------------------------------------ lifecycle (legacy)

    def _initialize(self, request: Request) -> dict[str, Any]:
        if self.legacy is not None:
            raise JsonRpcError(INVALID_REQUEST, "Invalid Request: initialize was already called on this connection")
        params = parse_params(InitializeParams, request.params, "initialize")
        version = negotiate_legacy(params.protocolVersion)
        self.legacy = LegacySession(version, params.clientInfo.model_dump(), params.capabilities)
        revision = self.legacy.revision
        log.info("legacy session: client asked for %s, negotiated %s", params.protocolVersion, version)
        return {
            "protocolVersion": version,
            "capabilities": self.server.capabilities(),
            "serverInfo": self.server.server_info(revision),
            "instructions": INSTRUCTIONS,
        }

    async def _ping(self, call: Call) -> dict[str, Any]:
        return {}

    async def _set_level(self, call: Call) -> dict[str, Any]:
        params = parse_params(SetLevelParams, call.request.params, "logging/setLevel")
        assert self.legacy is not None
        self.legacy.log_threshold = LOG_LEVELS.index(params.level)
        return {}

    # ------------------------------------------------------------------ discovery (modern)

    async def _discover(self, call: Call) -> dict[str, Any]:
        return {
            "supportedVersions": list(SUPPORTED_VERSIONS),
            "capabilities": self.server.capabilities(),
            "instructions": INSTRUCTIONS,
            "ttlMs": self.server.options.discover_ttl_ms,
            "cacheScope": "public",
        }

    async def _listen(self, call: Call) -> dict[str, Any]:
        params = parse_params(ListenParams, call.request.params, "subscriptions/listen")
        honoured: dict[str, Any] = {}
        if params.notifications.toolsListChanged:
            honoured["toolsListChanged"] = True
        subscription = Subscription(call.request.id, bool(honoured.get("toolsListChanged")), call.notify)
        self.subscriptions[subscription.id] = subscription
        try:
            await call.notify(notification("notifications/subscriptions/acknowledged",
                                           {"_meta": {META_SUBSCRIPTION_ID: subscription.id},
                                            "notifications": honoured}))
            await subscription.done.wait()
        finally:
            self.subscriptions.pop(subscription.id, None)
        return {"_meta": {META_SUBSCRIPTION_ID: subscription.id}}

    # ------------------------------------------------------------------ tools

    async def _tools_list(self, call: Call) -> dict[str, Any]:
        params = parse_params(PaginatedParams, call.request.params, "tools/list")
        tools = self.server.visible_tools(call.principal)
        fingerprint = hashlib.sha256("\n".join(t.name for t in tools).encode()).hexdigest()[:16]
        offset = 0 if params.cursor is None else _decode_cursor(params.cursor, fingerprint, len(tools))
        size = self.server.options.page_size
        page = tools[offset: offset + size]
        result: dict[str, Any] = {"tools": [tool.definition(call.revision) for tool in page]}
        if offset + size < len(tools):
            result["nextCursor"] = _encode_cursor(offset + size, fingerprint)
        if call.revision.modern:
            # The list depends on the caller's scopes, so shared caches must not reuse it.
            result.update(ttlMs=self.server.options.list_ttl_ms, cacheScope="private")
        return result

    async def _tools_call(self, call: Call) -> dict[str, Any]:
        params = parse_params(CallToolParams, call.request.params, "tools/call")
        started = time.perf_counter()
        arguments = params.arguments or {}
        revision = call.revision
        server = self.server

        def audit(decision: Decision, reason: str | None, is_error: bool) -> None:
            server.audit.write(AuditRecord(
                ts=utc_now(), transport=self.transport, protocol_version=revision.version,
                principal=call.principal.label, subject=call.principal.subject, request_id=call.request.id,
                tool=params.name, args_sha256=hash_arguments(arguments), decision=decision, reason=reason,
                is_error=is_error, duration_ms=round((time.perf_counter() - started) * 1000, 3)))

        async def refuse(decision: Decision, reason: str) -> dict[str, Any]:
            audit(decision, reason, True)
            await call.log("warning", {"tool": params.name, "decision": decision, "reason": reason})
            return _error_result(reason)

        tool = server.tool(params.name)
        if tool is None:
            audit("unknown_tool", "no such tool", True)
            raise JsonRpcError(INVALID_PARAMS, f"Unknown tool: {params.name}")
        profile = server.profile_of(call.principal)
        if profile is None:
            return await refuse("deny", "access denied: no policy profile matches this client (deny by default)")
        missing = sorted(tool.scopes - profile.scopes)
        if missing:
            return await refuse("deny", f"permission denied: {tool.name} needs scope {', '.join(missing)}, "
                                        f"which profile {call.principal.label!r} does not grant")
        limit = profile.rate_limit_for(tool.name)
        verdict = server.limiter.check(f"{call.principal.label}|{call.principal.subject}", tool.name, limit)
        if not verdict.allowed:
            return await refuse("deny", f"rate limit exceeded for {tool.name} ({limit}); "
                                        f"retry in {verdict.retry_after_s:.1f} s")
        try:
            args = tool.input_model.model_validate(arguments)
        except ValidationError as exc:
            errors = compact_errors(exc)
            audit("invalid", "argument validation failed", True)
            if revision.input_errors_as_tool_errors:
                lines = "\n".join(f"- {e['field']}: {e['message']}" for e in errors)
                return _error_result(f"Invalid arguments for {tool.name}:\n{lines}")
            raise JsonRpcError(INVALID_PARAMS, f"Invalid arguments for tool {tool.name}", {"errors": errors}) from None

        ctx = ToolContext(principal=call.principal, revision=revision, notify=call.notify,
                          progress_token=call.progress_token, log_threshold=call.log_threshold,
                          inflight=call.inflight)
        await call.log("debug", {"tool": tool.name, "event": "start"})
        try:
            output = await tool.run(args, ctx)
            structured = tool.dump_output(output)
        except ToolError as exc:
            return await refuse(exc.decision, str(exc))
        except JailError as exc:  # a tool resolved a path itself and the jail refused it
            return await refuse("deny", str(exc))
        except asyncio.CancelledError:
            audit("cancelled", "cancelled by client", True)
            raise
        except Exception:
            log.exception("tool %s failed", tool.name)
            audit("error", "internal error", True)
            raise JsonRpcError(INTERNAL_ERROR, f"Internal error while running {tool.name}") from None
        audit("allow", None, False)
        await call.log("info", {"tool": tool.name, "decision": "allow",
                                "duration_ms": round((time.perf_counter() - started) * 1000, 3)})
        # Spec: tools returning structured content SHOULD also return it serialised in a text block,
        # which is all that clients on revisions before 2025-06-18 understand.
        result: dict[str, Any] = {
            "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}],
        }
        if revision.structured_output:
            result["structuredContent"] = structured
        result["isError"] = False
        return result

    # ------------------------------------------------------------------ resources

    def _visible_resources(self, principal: Principal) -> list[ResourceSpec]:
        profile = self.server.profile_of(principal)
        if profile is None:
            return []
        return [spec for spec in RESOURCES if spec.scopes <= profile.scopes]

    async def _resources_list(self, call: Call) -> dict[str, Any]:
        params = parse_params(PaginatedParams, call.request.params, "resources/list")
        if params.cursor is not None:
            raise JsonRpcError(INVALID_PARAMS, "Invalid params: invalid cursor")
        resources = []
        for spec in self._visible_resources(call.principal):
            item: dict[str, Any] = {"uri": spec.uri, "name": spec.name}
            if call.revision.structured_output:
                item["title"] = spec.title
            item.update(description=spec.description, mimeType=spec.mime_type)
            resources.append(item)
        result: dict[str, Any] = {"resources": resources}
        if call.revision.modern:
            result.update(ttlMs=self.server.options.resource_ttl_ms, cacheScope="private")
        return result

    async def _templates_list(self, call: Call) -> dict[str, Any]:
        params = parse_params(PaginatedParams, call.request.params, "resources/templates/list")
        if params.cursor is not None:
            raise JsonRpcError(INVALID_PARAMS, "Invalid params: invalid cursor")
        result: dict[str, Any] = {"resourceTemplates": []}
        if call.revision.modern:
            result.update(ttlMs=self.server.options.resource_ttl_ms, cacheScope="public")
        return result

    async def _resources_read(self, call: Call) -> dict[str, Any]:
        params = parse_params(ReadResourceParams, call.request.params, "resources/read")
        spec = next((s for s in self._visible_resources(call.principal) if s.uri == params.uri), None)
        if spec is None:
            raise JsonRpcError(call.revision.resource_not_found_code, "Resource not found", {"uri": params.uri})
        text = await asyncio.to_thread(self._render_resource, spec, call.principal)
        result: dict[str, Any] = {"contents": [{"uri": spec.uri, "mimeType": spec.mime_type, "text": text}]}
        if call.revision.modern:
            result.update(ttlMs=self.server.options.resource_ttl_ms, cacheScope="private")
        return result

    def _render_resource(self, spec: ResourceSpec, principal: Principal) -> str:
        if spec.uri == "rawmcp://db/schema":
            sqlite_tool = next((t for t in self.server.all_tools() if t.name == "sqlite_query"), None)
            if not isinstance(sqlite_tool, SqliteQuery):
                raise JsonRpcError(INTERNAL_ERROR, "sqlite_query is not configured")
            return sqlite_tool.schema_sql()
        profile = self.server.profile_of(principal)
        assert profile is not None
        tools = {}
        for registered in self.server.all_tools():
            name = registered.name
            tool = self.server.tool(name)
            if tool is None:
                tools[name] = "disabled"
            else:
                missing = sorted(tool.scopes - profile.scopes)
                tools[name] = "allowed" if not missing else "needs " + ", ".join(missing)
        policy = self.server.policy
        return json.dumps({
            "profile": principal.label,
            "scopes": sorted(profile.scopes),
            "rate_limits": {tool: str(limit) for tool, limit in profile.rate_limits.items()},
            "tools": tools,
            "fetch_allow_domains": list(policy.fetch.allow_domains),
            "sandbox": {"timeout_s": policy.sandbox.timeout_s, "memory_mb": policy.sandbox.memory_mb,
                        "max_output_bytes": policy.sandbox.max_output_bytes},
        }, indent=2)


def check_modern_meta(meta: dict[str, Any]) -> tuple[Revision, int | None]:
    """Validate the per-request ``_meta`` envelope of a modern (2026-07-28) request.

    Returns the revision and the log threshold (``None`` when the client did not opt in to
    log notifications). Raises ``-32022`` for unsupported versions and ``-32602`` for missing
    or malformed required fields; on HTTP both map to ``400 Bad Request``.
    """
    version = meta.get(META_PROTOCOL_VERSION)
    if not isinstance(version, str):
        raise JsonRpcError(INVALID_PARAMS, f"Invalid params: _meta[{META_PROTOCOL_VERSION!r}] must be a string")
    if version not in MODERN_VERSIONS:
        hint = (f"; {version} uses the initialize handshake instead of per-request _meta"
                if version in SUPPORTED_VERSIONS else "")
        raise JsonRpcError(UNSUPPORTED_PROTOCOL_VERSION, f"Unsupported protocol version{hint}",
                           {"supported": list(SUPPORTED_VERSIONS), "requested": version})
    if not isinstance(meta.get(META_CLIENT_CAPABILITIES), dict):
        raise JsonRpcError(INVALID_PARAMS, f"Invalid params: missing required _meta field {META_CLIENT_CAPABILITIES!r}")
    info = meta.get(META_CLIENT_INFO)
    if info is not None:
        try:
            Implementation.model_validate(info)
        except ValidationError:
            raise JsonRpcError(INVALID_PARAMS, f"Invalid params: malformed _meta[{META_CLIENT_INFO!r}]") from None
    level = meta.get(META_LOG_LEVEL)
    if level is not None and level not in LOG_LEVELS:
        raise JsonRpcError(INVALID_PARAMS, f"Invalid params: unknown log level {level!r}", {"levels": list(LOG_LEVELS)})
    return REVISIONS[version], (LOG_LEVELS.index(level) if level is not None else None)

def _progress_token(meta: dict[str, Any]) -> str | int | None:
    token = meta.get("progressToken")
    if token is None:
        return None
    if isinstance(token, bool) or not isinstance(token, (str, int)):
        raise JsonRpcError(INVALID_PARAMS, "Invalid params: progressToken must be a string or an integer")
    return token


def _error_result(message: str) -> dict[str, Any]:
    """A tool execution error: a normal result with ``isError: true``."""
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _encode_cursor(offset: int, fingerprint: str) -> str:
    raw = json.dumps({"o": offset, "f": fingerprint}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str, fingerprint: str, total: int) -> int:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        offset, seen = data["o"], data["f"]
    except (ValueError, KeyError, TypeError, binascii.Error, UnicodeEncodeError):
        raise JsonRpcError(INVALID_PARAMS, "Invalid params: invalid cursor") from None
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 < offset < max(total, 1):
        raise JsonRpcError(INVALID_PARAMS, "Invalid params: invalid cursor")
    if seen != fingerprint:
        raise JsonRpcError(INVALID_PARAMS, "Invalid params: stale cursor, the tool list changed; start again")
    return offset


MODERN_METHODS: dict[str, Handler] = {
    "server/discover": Connection._discover,
    "subscriptions/listen": Connection._listen,
    "tools/list": Connection._tools_list,
    "tools/call": Connection._tools_call,
    "resources/list": Connection._resources_list,
    "resources/templates/list": Connection._templates_list,
    "resources/read": Connection._resources_read,
}
LEGACY_METHODS: dict[str, Handler] = {
    "ping": Connection._ping,
    "logging/setLevel": Connection._set_level,
    "tools/list": Connection._tools_list,
    "tools/call": Connection._tools_call,
    "resources/list": Connection._resources_list,
    "resources/templates/list": Connection._templates_list,
    "resources/read": Connection._resources_read,
}

