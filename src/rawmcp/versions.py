"""Protocol revisions this server speaks, and what each one allows.

The Model Context Protocol (MCP) has two eras:

* **modern** revisions (``2026-07-28``) are stateless: every request carries its protocol
  version and client capabilities in ``params._meta``; there is no handshake.
* **legacy** revisions (``2025-11-25`` and earlier) open a session with an ``initialize``
  request and a ``notifications/initialized`` notification.

This server is *dual-era*: it serves modern requests statelessly and still answers
``initialize`` for older clients. The feature flags below drive every version-dependent
decision (result shape, error codes, batching) so that the rules live in one place.
"""

from __future__ import annotations

from dataclasses import dataclass

MODERN_VERSIONS: tuple[str, ...] = ("2026-07-28",)
"""Revisions served statelessly through per-request ``_meta``."""

LEGACY_VERSIONS: tuple[str, ...] = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
"""Revisions reachable through the ``initialize`` handshake, newest first."""

SUPPORTED_VERSIONS: tuple[str, ...] = MODERN_VERSIONS + LEGACY_VERSIONS
LATEST_VERSION = MODERN_VERSIONS[0]
LATEST_LEGACY_VERSION = LEGACY_VERSIONS[0]

# Reserved `_meta` keys (2026-07-28, basic/index "_meta").
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_LOG_LEVEL = "io.modelcontextprotocol/logLevel"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
META_SUBSCRIPTION_ID = "io.modelcontextprotocol/subscriptionId"


@dataclass(frozen=True)
class Revision:
    """Feature flags for one protocol revision."""

    version: str
    modern: bool
    batching: bool
    """JSON-RPC batches: added in 2025-03-26, removed again in 2025-06-18."""
    tool_annotations: bool
    """``Tool.annotations`` and ``notifications/progress`` ``message`` (2025-03-26+)."""
    structured_output: bool
    """``outputSchema``, ``structuredContent`` and ``title`` fields (2025-06-18+)."""
    icons_and_descriptions: bool
    """``icons`` and ``Implementation.description`` (2025-11-25+)."""
    input_errors_as_tool_errors: bool
    """SEP-1303 (2025-11-25+): argument validation failures are tool execution errors
    (``isError: true``) rather than JSON-RPC ``-32602`` protocol errors."""

    @property
    def resource_not_found_code(self) -> int:
        """``-32002`` up to 2025-11-25; ``-32602`` (Invalid params) from 2026-07-28 (SEP-2164)."""
        return -32602 if self.modern else -32002


REVISIONS: dict[str, Revision] = {
    "2026-07-28": Revision("2026-07-28", True, False, True, True, True, True),
    "2025-11-25": Revision("2025-11-25", False, False, True, True, True, True),
    "2025-06-18": Revision("2025-06-18", False, False, True, True, False, False),
    "2025-03-26": Revision("2025-03-26", False, True, True, False, False, False),
    "2024-11-05": Revision("2024-11-05", False, False, False, False, False, False),
}


def negotiate_legacy(requested: str) -> str:
    """Pick the legacy revision to answer an ``initialize`` request with.

    Per the legacy lifecycle rules the server echoes the requested version when it supports
    it, and otherwise offers the latest version it does support.
    """
    return requested if requested in LEGACY_VERSIONS else LATEST_LEGACY_VERSION
