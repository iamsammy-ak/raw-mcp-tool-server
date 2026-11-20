"""Talk to the server with nothing but JSON lines over a pipe.

usage: PYTHONPATH=src python examples/raw_session.py
"""

from __future__ import annotations

import json
from pathlib import Path

from rawmcp.client import RawStdioClient, server_command

POLICY = Path(__file__).resolve().parent / "policy.yaml"

argv, env = server_command(POLICY, "reader")
with RawStdioClient(argv, env=env) as client:
    discover, _ = client.request("server/discover")
    print("versions:", discover["result"]["supportedVersions"])

    listing, _ = client.request("tools/list")
    print("tools:", [tool["name"] for tool in listing["result"]["tools"]])

    call, _ = client.request("tools/call", {"name": "sqlite_query", "arguments": {
        "sql": "SELECT category, COUNT(*) AS products FROM products GROUP BY category ORDER BY category"}})
    print("rows:", call["result"]["structuredContent"]["rows"])

    denied, _ = client.request("tools/call", {"name": "write_file",
                                              "arguments": {"path": "notes/x.txt", "content": "hi"}})
    print("write_file:", json.dumps(denied["result"]["content"][0]["text"]))
