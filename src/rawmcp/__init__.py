"""rawmcp: a Model Context Protocol (MCP) tool server built on raw JSON-RPC 2.0.

No MCP SDK at runtime: framing, version negotiation, schemas, permissions and the sandbox are
implemented here on top of the standard library and Pydantic.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
