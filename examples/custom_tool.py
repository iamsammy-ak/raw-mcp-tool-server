"""Add your own tool: a strict input model, an output model, required scopes and ``run``.

usage: PYTHONPATH=src python examples/custom_tool.py
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from pydantic import Field

from rawmcp.client import modern_meta
from rawmcp.context import Principal, ToolContext
from rawmcp.jail import Jail
from rawmcp.policy import load_policy
from rawmcp.server import McpServer
from rawmcp.tools import Tool, ToolError, ToolInput, ToolOutput, build_tools


class WordCountInput(ToolInput):
    path: str = Field(min_length=1, max_length=1024, description="Text file relative to the workspace.")


class WordCountOutput(ToolOutput):
    path: str
    lines: int
    words: int


class WordCount(Tool):
    name = "word_count"
    title = "Word count"
    description = "Count lines and words in a workspace text file."
    input_model = WordCountInput
    output_model = WordCountOutput
    scopes = frozenset({"fs:read"})

    def __init__(self, jail: Jail) -> None:
        self.jail = jail

    async def run(self, args: WordCountInput, ctx: ToolContext) -> WordCountOutput:
        path = self.jail.resolve(args.path)  # raises for traversal, absolute paths and escaping symlinks
        if not path.is_file():
            raise ToolError(f"not a file: {args.path}")
        text = path.read_text(encoding="utf-8", errors="replace")
        return WordCountOutput(path=self.jail.display(path), lines=len(text.splitlines()), words=len(text.split()))


async def main() -> None:
    policy = load_policy(Path(__file__).resolve().parent / "policy.yaml")
    server = McpServer(policy, tools=[*build_tools(policy), WordCount(Jail(policy.workspace))])
    replies: list[dict] = []

    async def send(message: dict) -> None:
        replies.append(message)

    connection = server.connect("in-process", Principal("reader", "example"), send)
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "word_count", "arguments": {"path": "notes/todo.txt"}, "_meta": modern_meta()}}
    await connection.feed(json.dumps(request))
    await connection.close(drain_timeout_s=5)
    print(json.dumps(replies[0]["result"]["structuredContent"]))
    schema = next(t for t in server.all_tools() if t.name == "word_count").input_schema()
    print(json.dumps(schema))


asyncio.run(main())
