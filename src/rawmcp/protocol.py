"""Pydantic models for the MCP request parameters this server accepts.

Field names follow the specification exactly (camelCase on the wire). Parameter objects
allow unknown keys because the specification lets requests carry extension fields and
``_meta``; the fields that matter are validated strictly.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, ValidationError

from rawmcp.jsonrpc import INVALID_PARAMS, JsonRpcError

LoggingLevel = Literal["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"]
LOG_LEVELS: tuple[str, ...] = ("debug", "info", "notice", "warning", "error", "critical", "alert", "emergency")
"""RFC 5424 severities, least to most severe."""


class _Params(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)


class Implementation(BaseModel):
    """``Implementation``: name and version of a client or server."""

    model_config = ConfigDict(extra="allow", strict=True)
    name: StrictStr
    version: StrictStr


class InitializeParams(_Params):
    """``initialize`` (legacy revisions only)."""

    protocolVersion: StrictStr
    capabilities: dict[str, Any]
    clientInfo: Implementation


class PaginatedParams(_Params):
    """``tools/list``, ``resources/list`` and ``resources/templates/list``."""

    cursor: StrictStr | None = None


class CallToolParams(_Params):
    """``tools/call``."""

    name: StrictStr = Field(min_length=1)
    arguments: dict[str, Any] | None = None


class ReadResourceParams(_Params):
    """``resources/read``."""

    uri: StrictStr = Field(min_length=1)


class SetLevelParams(_Params):
    """``logging/setLevel`` (legacy revisions only)."""

    level: LoggingLevel


class CancelledParams(_Params):
    """``notifications/cancelled``."""

    requestId: StrictStr | StrictInt
    reason: StrictStr | None = None


class SubscriptionFilter(BaseModel):
    """``SubscriptionFilter`` of ``subscriptions/listen`` (2026-07-28)."""

    model_config = ConfigDict(extra="allow", strict=True)
    toolsListChanged: StrictBool | None = None
    promptsListChanged: StrictBool | None = None
    resourcesListChanged: StrictBool | None = None
    resourceSubscriptions: list[StrictStr] | None = None


class ListenParams(_Params):
    """``subscriptions/listen`` (2026-07-28)."""

    notifications: SubscriptionFilter


def parse_params(model: type[_Params], params: dict[str, Any], method: str) -> Any:
    """Validate request params, mapping failures to JSON-RPC ``-32602 Invalid params``."""
    try:
        return model.model_validate(params)
    except ValidationError as exc:
        raise JsonRpcError(INVALID_PARAMS, f"Invalid params for {method}", {"errors": compact_errors(exc)}) from None


def compact_errors(exc: ValidationError) -> list[dict[str, str]]:
    """Pydantic errors reduced to ``{"field", "message"}`` pairs (no echoed input values)."""
    out = []
    for err in exc.errors(include_url=False, include_context=False, include_input=False):
        loc = ".".join(str(part) for part in err.get("loc", ())) or "(root)"
        out.append({"field": loc, "message": err.get("msg", "invalid")})
    return out
