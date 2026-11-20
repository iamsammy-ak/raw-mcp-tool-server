"""JSON-RPC 2.0 framing, written from the specification rather than borrowed from an SDK.

Everything that touches raw bytes lives here: decoding, classifying a decoded value into a
request, notification or response, and building response objects. Nothing in this module
knows about MCP methods; it only enforces the envelope rules of JSON-RPC 2.0 plus the two
extra constraints MCP places on it (request ids are strings or integers and never ``null``,
and ``params`` is always an object).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# MCP-reserved codes (2026-07-28).
HEADER_MISMATCH = -32020
MISSING_REQUIRED_CLIENT_CAPABILITY = -32021
UNSUPPORTED_PROTOCOL_VERSION = -32022
# Legacy (2025-11-25 and earlier) resource-not-found code.
RESOURCE_NOT_FOUND_LEGACY = -32002

RequestId = str | int
"""MCP narrows JSON-RPC ids to strings and integers; ``null`` is not allowed."""

MAX_NESTING_DEPTH = 64
"""Messages nested deeper than this are rejected before they reach any handler."""


class JsonRpcError(Exception):
    """An error that becomes a JSON-RPC error response.

    ``request_id`` is the id to echo, or ``None`` when the id could not be read
    (parse errors and some invalid requests); such responses omit ``id`` entirely,
    as the MCP schema allows.
    """

    def __init__(
        self,
        code: int,
        message: str,
        data: Any = None,
        request_id: RequestId | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
        self.request_id = request_id

    def to_response(self, request_id: RequestId | None = None) -> dict[str, Any]:
        """Render as a JSON-RPC error response object."""
        rid = request_id if request_id is not None else self.request_id
        return error_response(rid, self.code, self.message, self.data)


@dataclass(frozen=True)
class Request:
    """A JSON-RPC request: it has an id and expects exactly one response."""

    id: RequestId
    method: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Notification:
    """A JSON-RPC notification: no id, and the receiver must not reply."""

    method: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Response:
    """A JSON-RPC response sent *to* the server. MCP servers never issue requests, so these are ignored."""

    id: RequestId | None
    payload: dict[str, Any]


Message = Request | Notification | Response


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _depth(value: Any, limit: int) -> int:
    """Nesting depth of a decoded JSON value, stopping early once ``limit`` is exceeded."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        if level > deepest:
            deepest = level
            if deepest > limit:
                return deepest
        if isinstance(item, dict):
            stack.extend((child, level + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, level + 1) for child in item)
    return deepest


def decode(raw: bytes | str) -> Any:
    """Decode one wire message into a Python value.

    Raises ``JsonRpcError(PARSE_ERROR)`` for invalid UTF-8, invalid JSON (including the
    non-standard ``NaN``/``Infinity`` literals Python would otherwise accept) and values
    nested deeper than ``MAX_NESTING_DEPTH``.
    """
    try:
        text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        value = json.loads(text, parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise JsonRpcError(PARSE_ERROR, "Parse error", {"detail": _short(str(exc))}) from None
    if _depth(value, MAX_NESTING_DEPTH) > MAX_NESTING_DEPTH:
        raise JsonRpcError(PARSE_ERROR, "Parse error", {"detail": f"nesting deeper than {MAX_NESTING_DEPTH}"})
    return value


def _short(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def is_valid_id(value: Any) -> bool:
    """MCP request ids are strings or integers (JSON booleans are not integers)."""
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


def classify(obj: Any) -> Message:
    """Turn one decoded JSON value into a ``Request``, ``Notification`` or ``Response``.

    Raises ``JsonRpcError(INVALID_REQUEST)`` when the value is not a valid JSON-RPC 2.0
    message under MCP's constraints. The error carries the request id whenever it could
    be read, so the caller can echo it.
    """
    if not isinstance(obj, dict):
        raise JsonRpcError(INVALID_REQUEST, "Invalid Request: a message must be a JSON object")
    raw_id = obj.get("id")
    readable_id: RequestId | None = raw_id if is_valid_id(raw_id) else None
    if obj.get("jsonrpc") != "2.0":
        raise JsonRpcError(INVALID_REQUEST, 'Invalid Request: "jsonrpc" must be exactly "2.0"', request_id=readable_id)

    if "method" in obj:
        method = obj["method"]
        if not isinstance(method, str) or not method:
            raise JsonRpcError(INVALID_REQUEST, 'Invalid Request: "method" must be a non-empty string',
                               request_id=readable_id)
        if "result" in obj or "error" in obj:
            raise JsonRpcError(INVALID_REQUEST, "Invalid Request: a request cannot carry result or error",
                               request_id=readable_id)
        params = obj.get("params", {})
        if not isinstance(params, dict):
            raise JsonRpcError(INVALID_REQUEST, 'Invalid Request: "params" must be an object',
                               request_id=readable_id)
        if "id" not in obj:
            return Notification(method, params)
        if raw_id is None:
            raise JsonRpcError(INVALID_REQUEST, 'Invalid Request: "id" must not be null')
        if readable_id is None:
            raise JsonRpcError(INVALID_REQUEST, 'Invalid Request: "id" must be a string or an integer')
        return Request(readable_id, method, params)

    if ("result" in obj) != ("error" in obj) and "id" in obj:
        return Response(readable_id, obj)
    raise JsonRpcError(INVALID_REQUEST, "Invalid Request: not a request, notification or response",
                       request_id=readable_id)


def result_response(request_id: RequestId, result: dict[str, Any]) -> dict[str, Any]:
    """Build a successful response object."""
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(request_id: RequestId | None, code: int, message: str, data: Any = None) -> dict[str, Any]:
    """Build an error response object; ``id`` is omitted when it could not be determined."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    response: dict[str, Any] = {"jsonrpc": "2.0"}
    if request_id is not None:
        response["id"] = request_id
    response["error"] = error
    return response


def notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a notification object."""
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    return message


def encode(message: dict[str, Any] | list[dict[str, Any]]) -> bytes:
    """Serialise one message (or a batch reply) as a single UTF-8 line without embedded newlines.

    ``allow_nan=False`` guarantees the output is strict JSON; ``json.dumps`` escapes any newline
    inside strings, so the framing rule of the stdio transport holds by construction.
    """
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
