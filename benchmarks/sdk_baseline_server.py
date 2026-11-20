"""Baseline for the benchmark: the same ``calculate`` tool served by the official MCP Python SDK.

Only the benchmark uses this file (the SDK is a development dependency). The tool body calls
the same ``rawmcp.tools.calculate.evaluate`` function, so a latency difference between the two
servers is protocol and framework overhead, not tool work.

usage: python benchmarks/sdk_baseline_server.py   (speaks MCP over stdio)
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from rawmcp.tools.calculate import evaluate

server = MCPServer("sdk-baseline")


@server.tool()
def calculate(expression: str) -> dict[str, object]:
    """Evaluate an arithmetic expression."""
    value = evaluate(expression)
    return {"expression": expression, "result": value, "type": type(value).__name__}


if __name__ == "__main__":
    server.run("stdio")
