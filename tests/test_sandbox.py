"""The run_python sandbox: process isolation, limits and the audit hook."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

from rawmcp.policy import SandboxPolicy
from rawmcp.sandbox import Sandbox

pytestmark = pytest.mark.subprocess

POLICY = SandboxPolicy(timeout_s=5, max_timeout_s=10, memory_mb=256, max_output_bytes=4096)


async def run(code: str, timeout: float = 5.0) -> object:
    return await Sandbox(POLICY).run(code, timeout)


async def test_runs_code_and_captures_output() -> None:
    result = await run("import math, sys\nprint(math.factorial(5))\nprint('oops', file=sys.stderr)")
    assert result.exit_code == 0 and result.stdout.strip() == "120" and "oops" in result.stderr


async def test_exceptions_are_reported_not_raised() -> None:
    result = await run("raise ValueError('boom')")
    assert result.exit_code == 1 and "ValueError: boom" in result.stderr and not result.timed_out


async def test_timeout_kills_infinite_loop() -> None:
    result = await run("while True:\n    pass", timeout=0.5)
    assert result.timed_out and result.killed_reason == "timeout" and result.duration_ms < 5000


async def test_output_is_capped_and_runaway_printer_killed() -> None:
    result = await run("while True:\n    print('x' * 1000)")
    assert result.truncated and len(result.stdout.encode()) <= POLICY.max_output_bytes
    assert result.killed_reason == "output limit"


async def test_environment_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RAWMCP_TEST_SECRET", "s3cr3t")
    result = await run("import os\nprint(sorted(os.environ))\nprint(os.environ.get('RAWMCP_TEST_SECRET'))")
    assert "s3cr3t" not in result.stdout and "RAWMCP_TEST_SECRET" not in result.stdout


async def test_runs_in_a_fresh_temporary_directory_that_is_removed() -> None:
    result = await run("import os\nprint(os.getcwd())\nprint(os.listdir('.'))")
    cwd, listing = result.stdout.splitlines()
    assert Path(cwd).name.startswith("rawmcp-sbx-") and listing == "['snippet.py']"
    assert not Path(cwd).exists()


@pytest.mark.parametrize("module", ["socket", "subprocess", "ctypes", "urllib.request", "multiprocessing"])
async def test_network_process_and_ffi_modules_are_blocked(module: str) -> None:
    result = await run(f"import {module}")
    assert result.exit_code != 0 and "blocked in the sandbox" in result.stderr


async def test_process_spawning_is_blocked() -> None:
    result = await run("import os\nos.system('echo hi')")
    assert result.exit_code != 0 and "blocked" in result.stderr and "hi" not in result.stdout


async def test_reading_outside_the_sandbox_is_blocked() -> None:
    outside = Path(tempfile.gettempdir()) / "rawmcp-outside-test.txt"
    outside.write_text("private", encoding="utf-8")
    try:
        result = await run(f"print(open({str(outside)!r}).read())")
    finally:
        outside.unlink()
    assert result.exit_code != 0 and "private" not in result.stdout and "blocked" in result.stderr


async def test_writing_inside_the_sandbox_works() -> None:
    result = await run("open('out.txt', 'w').write('ok')\nprint(open('out.txt').read())")
    assert result.exit_code == 0 and result.stdout.strip() == "ok"


async def test_stdlib_imports_still_work() -> None:
    result = await run("import json, statistics, re, datetime\nprint(statistics.mean([1, 2, 3]))")
    assert result.exit_code == 0 and result.stdout.strip() == "2"


@pytest.mark.skipif(os.name != "posix" or sys.platform == "darwin", reason="RLIMIT_AS is enforced on Linux only")
async def test_memory_limit_on_linux() -> None:
    result = await run("x = bytearray(1024 * 1024 * 1024)\nprint('allocated')")
    assert "allocated" not in result.stdout and "MemoryError" in result.stderr


async def test_run_python_tool_end_to_end(harness) -> None:
    h = harness("analyst")
    response = await h.call("run_python", {"code": "print(6 * 7)"}, progressToken=9)
    result = response["result"]["structuredContent"]
    assert result["stdout"].strip() == "42" and result["exit_code"] == 0
    assert result["enforcement"].startswith("posix" if os.name == "posix" else "timeout")
    progress = [m["params"]["progress"] for m in h.notifications("notifications/progress")]
    assert progress == [0, 1]
