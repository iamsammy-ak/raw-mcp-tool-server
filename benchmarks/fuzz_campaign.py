"""Black-box fuzz campaign against a live stdio server process.

Sends N malformed or mutated messages, each followed by a sentinel ``ping`` with a unique id,
and reads everything up to the sentinel's reply. Checks that the process never dies, that every
stdout line is a valid JSON-RPC message, and that no input provokes an internal error (-32603).
Seeded, so a run is reproducible.

usage: PYTHONPATH=src python benchmarks/fuzz_campaign.py [--cases 10000] [--seed 7]
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rawmcp.client import modern_meta  # noqa: E402

RESULTS = ROOT / "benchmarks" / "results"
POLICY = """\
version: 1
workspace: ./workspace
profiles:
  fuzz:
    scopes: [fs:read, db:read]
"""

SEEDS: list[dict[str, Any]] = [
    {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": modern_meta()}},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": modern_meta()}},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "calculate", "arguments": {"expression": "1+2"}, "_meta": modern_meta()}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
     "params": {"name": "read_file", "arguments": {"path": "a.txt"}, "_meta": modern_meta()}},
    {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
     "params": {"name": "sqlite_query", "arguments": {"sql": "SELECT 1"}, "_meta": modern_meta()}},
    {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
     "params": {"name": "list_dir", "arguments": {}, "_meta": modern_meta()}},
    {"jsonrpc": "2.0", "id": 7, "method": "resources/read",
     "params": {"uri": "rawmcp://db/schema", "_meta": modern_meta()}},
    {"jsonrpc": "2.0", "id": 8, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "f", "version": "1"}}},
    {"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {"cursor": "abc", "_meta": modern_meta()}},
    {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}},
    {"jsonrpc": "2.0", "id": 10, "method": "logging/setLevel", "params": {"level": "info"}},
]


def random_json(rng: random.Random, depth: int = 0) -> Any:
    choice = rng.randrange(9 if depth < 4 else 6)
    if choice == 0:
        return None
    if choice == 1:
        return rng.choice([True, False])
    if choice == 2:
        return rng.choice([0, -1, 1, 2**31, -(2**63), 10**30, rng.randrange(-1000, 1000)])
    if choice == 3:
        return rng.choice([0.5, -1e308, 1e-300, rng.random()])
    if choice in (4, 5):
        alphabet = "abc/._-:{}[]\"'\\\x00é世\U0001f600 \t"
        return "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 20)))
    if choice in (6, 7):
        return {f"k{rng.randrange(5)}": random_json(rng, depth + 1) for _ in range(rng.randrange(0, 4))}
    return [random_json(rng, depth + 1) for _ in range(rng.randrange(0, 4))]


def mutate(rng: random.Random, message: dict[str, Any]) -> Any:
    """Delete or replace one field at a random depth (type confusion, missing fields), maybe change the id."""
    message = json.loads(json.dumps(message))
    target: Any = message
    while isinstance(target, dict) and target and rng.random() < 0.6:
        key = rng.choice(list(target))
        if not isinstance(target[key], dict):
            break
        target = target[key]
    if isinstance(target, dict) and target:
        key = rng.choice(list(target))
        if rng.random() < 0.4:
            del target[key]
        else:
            target[key] = random_json(rng)
    if isinstance(message, dict) and "id" in message:
        message["id"] = rng.choice([message["id"], f"f{rng.randrange(10**6)}", rng.randrange(10**6)])
    return message


def make_case(rng: random.Random) -> tuple[str, bytes]:
    kind = rng.choices(["bytes", "json", "mutated", "truncated", "deep", "batch", "big"],
                       weights=[12, 12, 40, 12, 8, 10, 6])[0]
    if kind == "bytes":
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 120)))
        return kind, data.replace(b"\n", b" ")
    if kind == "json":
        return kind, json.dumps(random_json(rng)).encode()
    if kind == "mutated":
        return kind, json.dumps(mutate(rng, rng.choice(SEEDS))).encode()
    if kind == "truncated":
        text = json.dumps(rng.choice(SEEDS)).encode()
        return kind, text[: rng.randrange(1, len(text))]
    if kind == "deep":
        depth = rng.randrange(10, 3000)
        head = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":'
        return kind, head + b'{"a":' * depth + b"1" + b"}" * depth + b"}"
    if kind == "batch":
        return kind, json.dumps([mutate(rng, rng.choice(SEEDS)) for _ in range(rng.randrange(0, 5))]).encode()
    blob = "x" * rng.randrange(1_000, 200_000)
    return kind, json.dumps({"jsonrpc": "2.0", "id": "big", "method": "tools/call",
                             "params": {"name": "calculate", "arguments": {"expression": blob},
                                        "_meta": modern_meta()}}).encode()


def valid_reply(message: Any) -> bool:
    if isinstance(message, list):
        return bool(message) and all(valid_reply(m) for m in message)
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return False
    if "method" in message:
        return "id" not in message
    if "error" in message:
        err = message["error"]
        return isinstance(err, dict) and isinstance(err.get("code"), int) and isinstance(err.get("message"), str)
    return isinstance(message.get("result"), dict)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    kinds: collections.Counter[str] = collections.Counter()
    codes: collections.Counter[str] = collections.Counter()
    invalid_lines = 0
    internal_errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="rawmcp-fuzz-") as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "workspace").mkdir()
        (tmp / "workspace" / "a.txt").write_text("fuzz target\n", encoding="utf-8")
        (tmp / "policy.yaml").write_text(POLICY, encoding="utf-8")
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        proc = subprocess.Popen([sys.executable, "-m", "rawmcp", "serve", "--policy", str(tmp / "policy.yaml"),
                                 "--profile", "fuzz", "--no-watch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env, cwd=tmp)
        assert proc.stdin is not None and proc.stdout is not None
        started = time.perf_counter()
        for n in range(args.cases):
            kind, data = make_case(rng)
            kinds[kind] += 1
            sentinel = f"sentinel-{n}"
            proc.stdin.write(data + b"\n" + json.dumps({"jsonrpc": "2.0", "id": sentinel, "method": "ping"}).encode()
                             + b"\n")
            proc.stdin.flush()
            while True:
                line = proc.stdout.readline()
                if not line:
                    raise SystemExit(f"server exited during case {n} ({kind}) with code {proc.poll()}")
                try:
                    message = json.loads(line)
                except ValueError:
                    invalid_lines += 1
                    continue
                if not valid_reply(message):
                    invalid_lines += 1
                if isinstance(message, dict) and message.get("id") == sentinel:
                    break
                for item in message if isinstance(message, list) else [message]:
                    if isinstance(item, dict) and "error" in item:
                        code = item["error"].get("code")
                        codes[str(code)] += 1
                        if code == -32603:
                            internal_errors.append(data[:200].decode("utf-8", "replace"))
                    elif isinstance(item, dict) and "result" in item:
                        is_error = isinstance(item["result"], dict) and item["result"].get("isError")
                        codes["result (isError)" if is_error else "result"] += 1
        elapsed = time.perf_counter() - started
        proc.stdin.close()
        exit_code = proc.wait(timeout=30)

    summary = {
        "command": f"PYTHONPATH=src python benchmarks/fuzz_campaign.py --cases {args.cases} --seed {args.seed}",
        "cases": args.cases, "seed": args.seed, "case_kinds": dict(sorted(kinds.items())),
        "reply_codes": dict(sorted(codes.items())), "invalid_stdout_lines": invalid_lines,
        "internal_errors": len(internal_errors), "internal_error_samples": internal_errors[:5],
        "server_crashes": 0, "clean_exit_code": exit_code, "seconds": round(elapsed, 1),
        "cases_per_second": round(args.cases / elapsed, 1),
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "fuzz_campaign.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lines = ["# Fuzz campaign", "", f"Command: `{summary['command']}`", "",
             f"- cases: {args.cases} (seed {args.seed}), {summary['cases_per_second']} cases/s",
             "- server crashes: 0 (the process answered every sentinel and exited cleanly with code "
             f"{exit_code} at end of input)",
             f"- stdout lines that were not valid JSON-RPC: {invalid_lines}",
             f"- internal errors (-32603): {len(internal_errors)}", "",
             "| Case kind | count |", "|---|---:|", *[f"| {k} | {v} |" for k, v in sorted(kinds.items())], "",
             "| Reply | count |", "|---|---:|", *[f"| {k} | {v} |" for k, v in sorted(codes.items())]]
    (RESULTS / "fuzz_campaign.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
