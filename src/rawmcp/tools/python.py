"""``run_python``: execute a snippet in the :mod:`rawmcp.sandbox`."""

from __future__ import annotations

from pydantic import Field

from rawmcp.context import ToolContext
from rawmcp.sandbox import Sandbox
from rawmcp.tools.base import Tool, ToolInput, ToolOutput


class RunPythonInput(ToolInput):
    code: str = Field(min_length=1, max_length=20_000, description="Python 3 source to run as a script.")
    timeout_s: float = Field(default=5.0, gt=0, le=300,
                             description="Wall-clock limit in seconds (capped by the server policy).")


class RunPythonOutput(ToolOutput):
    exit_code: int | None = Field(description="Process exit status; negative on POSIX when killed by a signal.")
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool = Field(description="True if stdout or stderr hit the output cap.")
    duration_ms: float
    killed_reason: str | None
    enforcement: str = Field(description="Which limits this platform enforces.")
    limits: dict[str, int | float]


class RunPython(Tool):
    name = "run_python"
    title = "Run Python (sandboxed)"
    description = (
        "Run a Python snippet in a separate process with no network or subprocess modules, an empty "
        "temporary directory, a scrubbed environment, a timeout and an output cap (plus memory/CPU "
        "limits on Linux and macOS). Only the standard library is available. A failing snippet is "
        "not a tool error: inspect exit_code and stderr."
    )
    input_model = RunPythonInput
    output_model = RunPythonOutput
    scopes = frozenset({"exec:python"})
    read_only = False
    idempotent = False
    open_world = False

    def __init__(self, sandbox: Sandbox) -> None:
        self.sandbox = sandbox

    async def run(self, args: RunPythonInput, ctx: ToolContext) -> RunPythonOutput:
        timeout = min(args.timeout_s, self.sandbox.policy.max_timeout_s)
        await ctx.progress(0, 1, "starting sandbox")
        result = await self.sandbox.run(args.code, timeout)
        await ctx.progress(1, 1, "finished")
        return RunPythonOutput(
            exit_code=result.exit_code, stdout=result.stdout, stderr=result.stderr, timed_out=result.timed_out,
            truncated=result.truncated, duration_ms=result.duration_ms, killed_reason=result.killed_reason,
            enforcement=self.sandbox.enforcement, limits=self.sandbox.limits())
