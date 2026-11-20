"""Connect with the official MCP Python SDK client (a development dependency, Python 3.11+).

The SDK probes with server/discover, sees 2026-07-28 and stays stateless; with mode="legacy"
it performs the initialize handshake instead. Either way it validates every result.

usage: PYTHONPATH=src python examples/sdk_client.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import Client
from mcp.client.stdio import StdioServerParameters

ROOT = Path(__file__).resolve().parents[1]
PARAMS = StdioServerParameters(
    command=sys.executable,
    args=["-m", "rawmcp", "serve", "--policy", str(ROOT / "examples" / "policy.yaml"), "--profile", "analyst"],
    env={"PYTHONPATH": str(ROOT / "src")},
)


async def main() -> None:
    for mode in ("auto", "legacy"):
        async with Client(PARAMS, mode=mode) as client:
            tools = await client.list_tools()
            result = await client.call_tool("run_python", {"code": "print(sum(i * i for i in range(10)))"})
            print(f"{mode:>6}: protocol {client.protocol_version}, {len(tools.tools)} tools, "
                  f"run_python stdout={result.structured_content['stdout'].strip()!r}")


asyncio.run(main())
