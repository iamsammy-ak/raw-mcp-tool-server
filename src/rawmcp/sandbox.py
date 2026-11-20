"""Run untrusted Python snippets in a separate, constrained subprocess.

Layers, from strongest to weakest:

* **Separate process** with a wall-clock timeout; the process (group, on POSIX) is killed on
  timeout, on output overflow and when the MCP request is cancelled.
* **POSIX resource limits** (``setrlimit``, hard = soft so the child cannot raise them):
  address space, CPU seconds, open files, maximum file size, no core dumps.
* **Minimal environment**: no inherited variables (so no API keys or tokens leak), a fresh
  temporary working directory that is deleted afterwards, ``-I -S -B`` (isolated mode, no
  site-packages, no bytecode writes) and UTF-8 mode.
* **Output cap**: stdout and stderr are read incrementally and truncated at a byte limit.
* **Audit hook** (defence in depth, *not* a security boundary): blocks importing network,
  process and FFI modules, spawning processes, and file access outside the sandbox directory
  and the Python installation.

Windows has no ``setrlimit``: memory, CPU and file-size limits are not enforced there, only
the timeout, output cap, environment scrubbing and audit hook. Use a container or a VM for
hostile code.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import sys
import tempfile
import time
from dataclasses import dataclass, field

from rawmcp.policy import SandboxPolicy

POSIX_LIMITS = os.name == "posix"

# Runs inside the child before the user's script. Kept as a string so the child never imports rawmcp.
LAUNCHER = r'''
import json, os, sys
cfg = json.loads(sys.argv[2])
try:
    import resource
except ImportError:
    resource = None
if resource is not None:
    def _limit(name, value):
        res = getattr(resource, name, None)
        if res is None:
            return
        soft, hard = resource.getrlimit(res)
        if hard != resource.RLIM_INFINITY:
            value = min(value, hard)
        try:
            resource.setrlimit(res, (value, value))
        except (ValueError, OSError):
            pass
    _limit("RLIMIT_AS", cfg["memory_bytes"])
    _limit("RLIMIT_CPU", cfg["cpu_s"])
    _limit("RLIMIT_NOFILE", cfg["max_open_files"])
    _limit("RLIMIT_FSIZE", cfg["max_file_bytes"])
    _limit("RLIMIT_CORE", 0)

_box = os.path.realpath(os.getcwd())
_read_roots = tuple({os.path.realpath(p) for p in (sys.base_prefix, sys.prefix, sys.exec_prefix, _box)})
_blocked_modules = frozenset(cfg["blocked_modules"])
_blocked_events = frozenset(cfg["blocked_events"])
_write_events = frozenset(cfg["write_events"])

def _inside(path, roots):
    if isinstance(path, int):
        return True
    try:
        real = os.path.realpath(os.fsdecode(path))
    except (TypeError, ValueError):
        return False
    return any(real == r or real.startswith(r.rstrip(os.sep) + os.sep) for r in roots)

def _hook(event, args):
    if event == "import":
        top = (args[0] or "").split(".")[0]
        if top in _blocked_modules:
            raise ImportError("module " + repr(top) + " is blocked in the sandbox")
    elif event in _blocked_events or event.startswith(("socket.", "winreg.", "ctypes.")):
        raise PermissionError(event + " is blocked in the sandbox")
    elif event == "open":
        path, mode, flags = args
        writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC))
        if not _inside(path, (_box,) if writing else _read_roots):
            raise PermissionError("file access outside the sandbox is blocked")
    elif event in ("os.listdir", "os.scandir"):
        if args and args[0] is not None and not _inside(args[0], _read_roots):
            raise PermissionError("listing directories outside the sandbox is blocked")
    elif event in _write_events:
        for item in args:
            if isinstance(item, (str, bytes, os.PathLike)) and not _inside(item, (_box,)):
                raise PermissionError(event + " outside the sandbox is blocked")

sys.addaudithook(_hook)
del json, resource
import runpy
runpy.run_path(sys.argv[1], run_name="__main__")
'''

BLOCKED_MODULES = (
    "socket", "_socket", "ssl", "_ssl", "select", "selectors", "asyncio", "subprocess", "_posixsubprocess",
    "multiprocessing", "_multiprocessing", "concurrent", "ctypes", "_ctypes", "cffi", "mmap", "pty",
    "urllib", "http", "ftplib", "smtplib", "telnetlib", "webbrowser", "_winapi", "winreg", "msvcrt",
)
BLOCKED_EVENTS = (
    "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty", "os.kill", "os.killpg",
    "os.startfile", "subprocess.Popen", "pty.spawn", "code.__new__",
    "os.chdir", "os.putenv", "os.unsetenv",
)
WRITE_EVENTS = (
    "os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.link", "os.symlink",
    "os.truncate", "os.utime", "shutil.rmtree", "shutil.move", "shutil.copyfile", "shutil.copytree",
)


@dataclass
class SandboxResult:
    """Outcome of one sandboxed run."""

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    duration_ms: float
    killed_reason: str | None = None


@dataclass
class _Capture:
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    truncated: bool = False


def child_environment(workdir: str) -> dict[str, str]:
    """A minimal environment: nothing inherited except what Windows needs to start Python."""
    env = {"HOME": workdir, "TMPDIR": workdir, "TEMP": workdir, "TMP": workdir, "LANG": "C.UTF-8",
           "PATH": os.defpath}
    if os.name == "nt":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
    return env


class Sandbox:
    """Runs Python source in a constrained subprocess. Thread-safe; limits concurrency with a semaphore."""

    def __init__(self, policy: SandboxPolicy) -> None:
        self.policy = policy
        self._slots: asyncio.Semaphore | None = None

    @property
    def enforcement(self) -> str:
        """Which limits the current platform actually enforces."""
        return "posix-rlimits+timeout+output-cap" if POSIX_LIMITS else "timeout+output-cap-only (no rlimits on Windows)"

    def limits(self) -> dict[str, int | float]:
        return {"memory_mb": self.policy.memory_mb, "cpu_s": self.policy.cpu_s,
                "max_open_files": self.policy.max_open_files, "max_file_bytes": self.policy.max_file_bytes,
                "max_output_bytes": self.policy.max_output_bytes}

    async def run(self, code: str, timeout_s: float) -> SandboxResult:
        """Execute ``code``; never raises for failures of the snippet itself."""
        timeout_s = min(timeout_s, self.policy.max_timeout_s)
        if self._slots is None:  # created lazily so it binds to the loop that runs the server
            self._slots = asyncio.Semaphore(self.policy.max_concurrent)
        async with self._slots:
            workdir = tempfile.mkdtemp(prefix="rawmcp-sbx-")
            try:
                return await self._run_in(workdir, code, timeout_s)
            finally:
                await _remove_tree(workdir)

    async def _run_in(self, workdir: str, code: str, timeout_s: float) -> SandboxResult:
        script = os.path.join(workdir, "snippet.py")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write(code)
        config = json.dumps({
            "memory_bytes": self.policy.memory_mb * 1024 * 1024, "cpu_s": self.policy.cpu_s,
            "max_open_files": self.policy.max_open_files, "max_file_bytes": self.policy.max_file_bytes,
            "blocked_modules": BLOCKED_MODULES, "blocked_events": BLOCKED_EVENTS, "write_events": WRITE_EVENTS,
        })
        started = time.perf_counter()
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-I", "-S", "-B", "-X", "utf8", "-c", LAUNCHER, script, config,
            cwd=workdir, env=child_environment(workdir), stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=POSIX_LIMITS,
        )
        capture = _Capture()
        cap = self.policy.max_output_bytes
        killed: list[str] = []

        def kill(reason: str) -> None:
            if proc.returncode is None and not killed:
                killed.append(reason)
                _kill_tree(proc)

        async def pump(stream: asyncio.StreamReader | None, buffer: bytearray) -> None:
            if stream is None:
                return
            while chunk := await stream.read(8192):
                room = cap - len(buffer)
                buffer += chunk[: max(room, 0)]
                if len(chunk) > room:
                    capture.truncated = True
                    kill("output limit")

        timed_out = False
        try:
            await asyncio.wait_for(
                asyncio.gather(pump(proc.stdout, capture.stdout), pump(proc.stderr, capture.stderr), proc.wait()),
                timeout=timeout_s)
        except asyncio.TimeoutError:
            timed_out = True
            kill("timeout")
            await proc.wait()
        finally:
            if proc.returncode is None:  # cancelled by the client: kill before propagating
                kill("cancelled")
                try:
                    await asyncio.shield(proc.wait())
                except asyncio.CancelledError:
                    pass
        return SandboxResult(
            exit_code=proc.returncode,
            stdout=capture.stdout.decode("utf-8", errors="replace"),
            stderr=capture.stderr.decode("utf-8", errors="replace"),
            timed_out=timed_out,
            truncated=capture.truncated,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            killed_reason=killed[0] if killed else None,
        )


def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    try:
        if sys.platform != "win32":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


async def _remove_tree(path: str) -> None:
    for _ in range(5):  # Windows may hold file handles briefly after the process exits
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.exists(path):
            return
        await asyncio.sleep(0.05)
