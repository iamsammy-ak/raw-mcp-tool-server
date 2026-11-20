"""tools/call latency and throughput over the stdio transport.

Each scenario launches a fresh server process and drives it with raw JSON-RPC lines. Latency is
measured from writing a request line to reading its response line (one request in flight).
Throughput pipelines requests with a fixed window of in-flight calls. If the official MCP SDK is
installed, the same ``calculate`` tool served by the SDK is measured as a baseline.

usage: PYTHONPATH=src python benchmarks/bench_stdio.py [--quick]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rawmcp import __version__  # noqa: E402
from rawmcp.client import modern_meta  # noqa: E402

RESULTS = ROOT / "benchmarks" / "results"
ASSETS = ROOT / "assets"

POLICY = """\
version: 1
workspace: ./workspace
profiles:
  bench:
    scopes: [fs:read, db:read, exec:python]
"""


class Pipe:
    """A server subprocess driven synchronously over its stdin/stdout."""

    def __init__(self, argv: list[str], env: dict[str, str], cwd: Path) -> None:
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, env=env, cwd=cwd)
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.stdin, self.stdout = self.proc.stdin, self.proc.stdout

    def send(self, message: dict[str, Any]) -> None:
        self.stdin.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")
        self.stdin.flush()

    def recv(self) -> dict[str, Any]:
        while True:
            message: dict[str, Any] = json.loads(self.stdout.readline())
            if "id" in message:
                return message

    def call(self, message: dict[str, Any]) -> tuple[float, dict[str, Any]]:
        start = time.perf_counter_ns()
        self.send(message)
        response = self.recv()
        return (time.perf_counter_ns() - start) / 1e6, response

    def handshake(self, version: str) -> None:
        _, response = self.call({"jsonrpc": "2.0", "id": "init", "method": "initialize",
                                 "params": {"protocolVersion": version, "capabilities": {},
                                            "clientInfo": {"name": "bench", "version": "1"}}})
        assert response["result"]["protocolVersion"] == version, response
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def close(self) -> None:
        self.stdin.close()
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def rawmcp_pipe(tmp: Path) -> Pipe:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    argv = [sys.executable, "-m", "rawmcp", "serve", "--policy", str(tmp / "policy.yaml"), "--profile", "bench",
            "--no-watch"]
    return Pipe(argv, env, tmp)


def sdk_pipe(tmp: Path) -> Pipe | None:
    try:
        import mcp  # noqa: F401
    except ImportError:
        return None
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return Pipe([sys.executable, str(ROOT / "benchmarks" / "sdk_baseline_server.py")], env, tmp)


def request(rid: int, method: str, params: dict[str, Any], modern: bool) -> dict[str, Any]:
    body = dict(params)
    if modern:
        body["_meta"] = modern_meta()
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": body}


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(q / 100 * (len(ordered) - 1))))
    return ordered[index]


def summarise(samples: list[float]) -> dict[str, float]:
    return {"n": len(samples), "p50_ms": round(percentile(samples, 50), 3), "p95_ms": round(percentile(samples, 95), 3),
            "p99_ms": round(percentile(samples, 99), 3), "mean_ms": round(statistics.fmean(samples), 3)}


def latency(pipe: Pipe, method: str, params: dict[str, Any], n: int, *, modern: bool, warmup: int) -> dict[str, float]:
    samples = []
    for i in range(warmup + n):
        elapsed, response = pipe.call(request(i + 1, method, params, modern))
        result = response.get("result")
        assert result is not None and not result.get("isError"), response
        if i >= warmup:
            samples.append(elapsed)
    return summarise(samples)


def throughput(pipe: Pipe, total: int, window: int, *, modern: bool) -> float:
    """Calls per second with up to ``window`` requests in flight.

    Single-threaded on the client side: send ``window`` requests, then one more per response.
    Pipe buffers (64 KiB) comfortably hold a window of 64 small messages, so this cannot deadlock.
    """
    params = {"name": "calculate", "arguments": {"expression": "2 * (3 + 4) ** 2"}}
    sent = 0
    start = time.perf_counter()
    while sent < min(window, total):
        pipe.send(request(10_000_000 + sent, "tools/call", params, modern))
        sent += 1
    for _ in range(total):
        response = pipe.recv()
        assert "result" in response, response
        if sent < total:
            pipe.send(request(10_000_000 + sent, "tools/call", params, modern))
            sent += 1
    return round(total / (time.perf_counter() - start), 1)


def cpu_calibration_ms() -> float:
    """Time of a fixed pure-Python loop: a rough indicator of how busy the machine was."""
    start = time.perf_counter()
    sum(i * i for i in range(2_000_000))
    return round((time.perf_counter() - start) * 1000, 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="fewer iterations (smoke run)")
    args = parser.parse_args()
    scale = 0.1 if args.quick else 1.0
    n_fast, n_mid, n_slow, n_tp = int(2000 * scale), int(800 * scale), max(3, int(20 * scale)), int(4000 * scale)
    calc = {"name": "calculate", "arguments": {"expression": "2 * (3 + 4) ** 2"}}
    read = {"name": "read_file", "arguments": {"path": "notes.txt"}}
    sql = {"name": "sqlite_query", "arguments": {"sql": "SELECT p.category, ROUND(SUM(i.quantity * i.unit_price), 2) "
                                                      "FROM order_items i JOIN products p ON p.id = i.product_id "
                                                      "GROUP BY p.category ORDER BY 2 DESC"}}
    py = {"name": "run_python", "arguments": {"code": "print(sum(range(1000)))"}}
    calibration_before = cpu_calibration_ms()

    results: dict[str, Any] = {"latency": {}, "throughput": {}}
    with tempfile.TemporaryDirectory(prefix="rawmcp-bench-") as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "workspace").mkdir()
        (tmp / "workspace" / "notes.txt").write_text("benchmark file\n" * 20, encoding="utf-8")
        (tmp / "policy.yaml").write_text(POLICY, encoding="utf-8")

        pipe = rawmcp_pipe(tmp)
        lat = results["latency"]
        lat["rawmcp · calculate (2026-07-28)"] = latency(pipe, "tools/call", calc, n_fast, modern=True, warmup=100)
        lat["rawmcp · tools/list (2026-07-28)"] = latency(pipe, "tools/list", {}, n_mid, modern=True, warmup=20)
        lat["rawmcp · read_file (2026-07-28)"] = latency(pipe, "tools/call", read, n_mid, modern=True, warmup=20)
        lat["rawmcp · sqlite_query join (2026-07-28)"] = latency(pipe, "tools/call", sql, n_mid, modern=True,
                                                                  warmup=20)
        lat["rawmcp · run_python sandbox (2026-07-28)"] = latency(pipe, "tools/call", py, n_slow, modern=True,
                                                                   warmup=2)
        pipe.close()

        legacy = rawmcp_pipe(tmp)
        legacy.handshake("2025-11-25")
        lat["rawmcp · calculate (2025-11-25 session)"] = latency(legacy, "tools/call", calc, n_fast, modern=False,
                                                                  warmup=100)
        legacy.close()

        for window in (1, 4, 16, 64):
            pipe = rawmcp_pipe(tmp)
            pipe.call(request(0, "tools/call", calc, True))
            results["throughput"][f"rawmcp · window {window}"] = throughput(pipe, n_tp, window, modern=True)
            pipe.close()

        baseline = sdk_pipe(tmp)
        if baseline is not None:
            from importlib.metadata import version

            results["sdk_version"] = version("mcp")
            lat["official SDK server · calculate (2026-07-28)"] = latency(baseline, "tools/call", calc, n_fast,
                                                                          modern=True, warmup=100)
            baseline.close()
            baseline = sdk_pipe(tmp)
            assert baseline is not None
            baseline.handshake("2025-11-25")
            lat["official SDK server · calculate (2025-11-25 session)"] = latency(
                baseline, "tools/call", calc, n_fast, modern=False, warmup=100)
            baseline.close()
            for window in (1, 4, 16, 64):
                baseline = sdk_pipe(tmp)
                assert baseline is not None
                baseline.call(request(0, "tools/call", calc, True))
                results["throughput"][f"official SDK server · window {window}"] = throughput(baseline, n_tp, window,
                                                                                            modern=True)
                baseline.close()

    results["environment"] = {
        "rawmcp": __version__, "python": platform.python_version(), "platform": platform.platform(terse=True),
        "cpus": os.cpu_count(), "cpu_calibration_ms_before": calibration_before,
        "cpu_calibration_ms_after": cpu_calibration_ms(), "quick": args.quick,
    }
    results["command"] = "PYTHONPATH=src python benchmarks/bench_stdio.py"
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "stdio_benchmark.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    write_markdown(results)
    plot(results)
    print(json.dumps(results, indent=2))


def write_markdown(results: dict[str, Any]) -> None:
    env = results["environment"]
    lines = ["# stdio benchmark", "",
             f"Command: `{results['command']}`  ", f"rawmcp {env['rawmcp']}, Python {env['python']}, "
             f"{env['platform']}, {env['cpus']} logical CPUs. CPU calibration loop: "
             f"{env['cpu_calibration_ms_before']} ms before, {env['cpu_calibration_ms_after']} ms after "
             "(higher means a busier machine).", "",
             "## Latency (one request in flight)", "", "| Scenario | n | p50 ms | p95 ms | p99 ms | mean ms |",
             "|---|---:|---:|---:|---:|---:|"]
    for name, row in results["latency"].items():
        cells = [row["n"], row["p50_ms"], row["p95_ms"], row["p99_ms"], row["mean_ms"]]
        lines.append(f"| {name} | " + " | ".join(str(c) for c in cells) + " |")
    lines += ["", "## Throughput (`calculate`, pipelined)", "", "| Server · in-flight window | calls/s |", "|---|---:|"]
    for name, value in results["throughput"].items():
        lines.append(f"| {name} | {value} |")
    if "sdk_version" in results:
        lines += ["", f"Baseline: official MCP Python SDK {results['sdk_version']} `MCPServer` running the same "
                      "`evaluate()` function (`benchmarks/sdk_baseline_server.py`)."]
    (RESULTS / "stdio_benchmark.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def plot(results: dict[str, Any]) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, (left, right) = plt.subplots(1, 2, figsize=(12, 4.6), facecolor="white",
                                      gridspec_kw={"width_ratios": [1.5, 1]})
    names = [n for n in results["latency"] if "run_python" not in n]
    p50 = [results["latency"][n]["p50_ms"] for n in names]
    p95 = [results["latency"][n]["p95_ms"] for n in names]
    ys = range(len(names))
    left.barh([y + 0.2 for y in ys], p50, height=0.4, color="#0F766E", label="p50")
    left.barh([y - 0.2 for y in ys], p95, height=0.4, color="#99D5CF", label="p95")
    left.set_yticks(list(ys), [n.replace(" · ", "\n", 1) for n in names], fontsize=8)
    left.invert_yaxis()
    left.set_xlabel("ms per tools/call round trip (lower is better)")
    left.set_title("Latency over stdio", fontsize=11)
    left.legend(frameon=False, fontsize=9)
    left.grid(axis="x", alpha=0.3)

    for server, colour in (("rawmcp", "#0F766E"), ("official SDK server", "#9CA3AF")):
        points = [(int(k.rsplit(" ", 1)[1]), v) for k, v in results["throughput"].items() if k.startswith(server)]
        if points:
            right.plot([p[0] for p in points], [p[1] for p in points], marker="o", color=colour, label=server)
    right.set_xscale("log", base=2)
    right.set_xlabel("requests in flight (pipelining window)")
    right.set_ylabel("calls / second")
    right.set_title("Throughput, calculate", fontsize=11)
    right.legend(frameon=False, fontsize=9)
    right.grid(alpha=0.3)
    fig.tight_layout()
    ASSETS.mkdir(exist_ok=True)
    fig.savefig(ASSETS / "benchmark.png", dpi=110, facecolor="white")


if __name__ == "__main__":
    main()
