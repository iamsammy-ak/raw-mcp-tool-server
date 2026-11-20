"""The built-in tools and a factory that wires them to a policy."""

from __future__ import annotations

from rawmcp.jail import Jail
from rawmcp.policy import Policy
from rawmcp.sandbox import Sandbox
from rawmcp.tools.base import PolicyDenied, Tool, ToolError, ToolInput, ToolOutput
from rawmcp.tools.calculate import Calculate
from rawmcp.tools.fetch import Fetcher, FetchUrl, Resolver
from rawmcp.tools.fs import ListDir, ReadFile, SearchFiles, WriteFile
from rawmcp.tools.python import RunPython
from rawmcp.tools.sqlite import SqliteQuery

__all__ = ["PolicyDenied", "Tool", "ToolError", "ToolInput", "ToolOutput", "build_tools"]


def build_tools(policy: Policy, *, fetcher: Fetcher | None = None, resolver: Resolver | None = None) -> list[Tool]:
    """Instantiate every built-in tool for ``policy``, sorted by name (a deterministic list order)."""
    jail = Jail(policy.workspace)
    tools: list[Tool] = [
        Calculate(),
        FetchUrl(policy.fetch, fetcher=fetcher, resolver=resolver),
        ListDir(jail),
        ReadFile(jail),
        RunPython(Sandbox(policy.sandbox)),
        SearchFiles(jail),
        SqliteQuery(policy.database),
        WriteFile(jail),
    ]
    return sorted(tools, key=lambda tool: tool.name)
