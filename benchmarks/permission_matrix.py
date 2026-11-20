"""Permission matrix and attack scenarios, measured against the real server core.

Uses the profiles from ``examples/policy.yaml`` with a temporary copy of its workspace. Network
access is replaced by a fake fetcher and resolver (nothing leaves the machine); the sandbox,
filesystem jail and SQLite guards run for real.

usage: PYTHONPATH=src python benchmarks/permission_matrix.py
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rawmcp.client import modern_meta  # noqa: E402
from rawmcp.context import Principal  # noqa: E402
from rawmcp.policy import policy_from_dict  # noqa: E402
from rawmcp.server import McpServer  # noqa: E402
from rawmcp.tools.fetch import FetchResponse  # noqa: E402

RESULTS = ROOT / "benchmarks" / "results"
PROFILES = ["anonymous", "reader", "analyst", "maintainer"]
CALLS: dict[str, dict[str, Any]] = {
    "calculate": {"expression": "6 * 7"},
    "list_dir": {"path": "."},
    "read_file": {"path": "README.md"},
    "search_files": {"query": "carrier"},
    "sqlite_query": {"sql": "SELECT COUNT(*) FROM orders"},
    "fetch_url": {"url": "https://example.com/"},
    "run_python": {"code": "print(1 + 1)"},
    "write_file": {"path": "scratch.txt", "content": "hello", "mode": "overwrite"},
}


class OfflineFetcher:
    """Pretends to be the network; follows one scripted redirect."""

    redirects = {"https://example.com/redirect": "https://attacker.net/steal"}

    def fetch(self, url: str, *, timeout: float, max_bytes: int, max_redirects: int,
              check_redirect: Callable[[str], None]) -> FetchResponse:
        while url in self.redirects:
            url = self.redirects[url]
            check_redirect(url)
        return FetchResponse(url, 200, "text/html", b"<html>Example Domain</html>", False)


def offline_resolver(host: str) -> list[str]:
    return {"example.com": ["93.184.215.14"], "docs.python.org": ["151.101.0.223"],
            "metadata.python.org": ["169.254.169.254"]}.get(host, ["203.0.113.10"])


class Runner:
    def __init__(self, server: McpServer) -> None:
        self.server = server
        self.ids = 0

    async def call(self, profile: str, tool: str, arguments: dict[str, Any]) -> tuple[str, str]:
        """Return (decision, message) for one tools/call."""
        outbox: list[Any] = []

        async def send(message: Any) -> None:
            outbox.append(message)

        principal = Principal(None if profile == "anonymous" else profile, "matrix")
        connection = self.server.connect("matrix", principal, send)
        self.ids += 1
        request = {"jsonrpc": "2.0", "id": self.ids, "method": "tools/call",
                   "params": {"name": tool, "arguments": arguments, "_meta": modern_meta()}}
        await connection.feed(json.dumps(request))
        while not any(isinstance(m, dict) and m.get("id") == self.ids for m in outbox):
            await asyncio.sleep(0.005)
        await connection.close()
        response = next(m for m in outbox if m.get("id") == self.ids)
        if "error" in response:
            return "protocol error", response["error"]["message"]
        record = self.server.audit.recent()[-1]
        text = response["result"]["content"][0]["text"]
        if record.decision == "allow":
            structured = response["result"].get("structuredContent", {})
            if tool == "run_python":
                if structured["killed_reason"]:
                    shown = len(structured["stdout"].encode())
                    detail = f"stdout kept {shown} bytes" if structured["truncated"] else ""
                    return f"ran, killed ({structured['killed_reason']})", detail
                detail = (structured["stderr"].strip().splitlines() or [structured["stdout"].strip()])[-1]
                return f"ran, exit {structured['exit_code']}", detail[:110]
            return "allow", ""
        return record.decision, " ".join(text.split())[:110]


async def build(tmp: Path) -> McpServer:
    data = yaml.safe_load((ROOT / "examples" / "policy.yaml").read_text(encoding="utf-8"))
    shutil.copytree(ROOT / "examples" / "workspace", tmp / "workspace")
    data["workspace"] = str(tmp / "workspace")
    data["audit_log"] = str(tmp / "audit.jsonl")
    data["profiles"]["throttled"] = {"scopes": ["fs:read"], "rate_limits": {"*": "3/minute"}}
    return McpServer(policy_from_dict(data, tmp), fetcher=OfflineFetcher(), resolver=offline_resolver)


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="rawmcp-matrix-") as tmpdir:
        tmp = Path(tmpdir)
        server = await build(tmp)
        runner = Runner(server)
        matrix: dict[str, dict[str, str]] = {}
        for tool, arguments in CALLS.items():
            matrix[tool] = {}
            for profile in PROFILES:
                decision, _ = await runner.call(profile, tool, arguments)
                matrix[tool][profile] = decision
        scopes = {t.name: sorted(t.scopes) for t in server.all_tools()}

        outside = tmp / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        link_note = "symlink to a file outside the workspace"
        try:
            os.symlink(outside, tmp / "workspace" / "link.txt")
            symlink_case: tuple[str, str, dict[str, Any]] = ("read_file", link_note, {"path": "link.txt"})
        except (OSError, NotImplementedError):
            symlink_case = ("", link_note, {})
        os.environ["RAWMCP_MATRIX_SECRET"] = "should-not-leak"
        attacks: list[tuple[str, str, dict[str, Any]]] = [
            ("read_file", "path traversal `../outside.txt`", {"path": "../outside.txt"}),
            ("read_file", "absolute path `/etc/passwd`", {"path": "/etc/passwd"}),
            ("read_file", "Windows drive path `C:\\Windows\\win.ini`", {"path": "C:\\Windows\\win.ini"}),
            symlink_case,
            ("write_file", "write outside via `../escape.txt`", {"path": "../escape.txt", "content": "x"}),
            ("sqlite_query", "`DROP TABLE orders`", {"sql": "DROP TABLE orders"}),
            ("sqlite_query", "`ATTACH DATABASE` another file", {"sql": "ATTACH DATABASE 'x.db' AS x"}),
            ("sqlite_query", "runaway recursive CTE", {"sql": "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL "
                                                              "SELECT x + 1 FROM c) SELECT COUNT(*) FROM c"}),
            ("fetch_url", "domain not on the allowlist", {"url": "https://attacker.net/"}),
            ("fetch_url", "plain `http://`", {"url": "http://example.com/"}),
            ("fetch_url", "allowlisted name resolving to 169.254.169.254", {"url": "https://metadata.python.org/"}),
            ("fetch_url", "redirect from allowlisted host to another domain", {"url": "https://example.com/redirect"}),
            ("run_python", "`import socket`", {"code": "import socket"}),
            ("run_python", "read a file outside the sandbox", {"code": f"print(open({str(outside)!r}).read())"}),
            ("run_python", "read the parent's environment", {"code": "import os\nprint(os.environ.get("
                                                                     "'RAWMCP_MATRIX_SECRET', 'not visible'))"}),
            ("run_python", "spawn a process with `os.system`", {"code": "import os\nos.system('whoami')"}),
            ("run_python", "infinite loop", {"code": "while True:\n    pass", "timeout_s": 1}),
            ("run_python", "print flood", {"code": "while True:\n    print('x' * 1000)"}),
            ("calculate", "code injection `__import__('os')`", {"expression": "__import__('os').system('id')"}),
            ("calculate", "huge power `9**9**9`", {"expression": "9**9**9"}),
            ("calculate", "wrong argument type (42)", {"expression": 42}),
        ]
        attack_rows = []
        for tool, scenario, arguments in attacks:
            if not tool:
                attack_rows.append({"scenario": scenario, "tool": "read_file", "profile": "maintainer",
                                    "decision": "not run (symlinks need privileges on this OS)", "detail": ""})
                continue
            decision, detail = await runner.call("maintainer", tool, arguments)
            attack_rows.append({"scenario": scenario, "tool": tool, "profile": "maintainer", "decision": decision,
                                "detail": detail})
        throttled = [(await runner.call("throttled", "read_file", {"path": "README.md"}))[0] for _ in range(4)]
        attack_rows.append({"scenario": "4 calls under a 3/minute limit", "tool": "read_file", "profile": "throttled",
                            "decision": " → ".join(throttled), "detail": ""})
        del os.environ["RAWMCP_MATRIX_SECRET"]
        audit_lines = len((tmp / "audit.jsonl").read_text(encoding="utf-8").splitlines())

    result = {"command": "PYTHONPATH=src python benchmarks/permission_matrix.py", "matrix": matrix,
              "scopes": scopes, "attacks": attack_rows, "audit_lines": audit_lines}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "permission_matrix.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    write_markdown(result)
    print(f"wrote {RESULTS / 'permission_matrix.md'}")


def write_markdown(result: dict[str, Any]) -> None:
    mark = {"allow": "✅ allow", "deny": "⛔ deny"}
    lines = ["# Permission matrix", "", f"Command: `{result['command']}`", "",
             "Profiles from `examples/policy.yaml`; `anonymous` is a caller whose token matches no profile.", "",
             "| Tool | Required scopes | " + " | ".join(PROFILES) + " |",
             "|---|---|" + "---|" * len(PROFILES)]
    for tool, row in result["matrix"].items():
        cells = [mark.get(row[p], row[p]) if not row[p].startswith("ran") else "✅ allow" for p in PROFILES]
        lines.append(f"| `{tool}` | {', '.join(result['scopes'][tool]) or '(none)'} | " + " | ".join(cells) + " |")
    lines += ["", "## Attack scenarios", "", "| Scenario | Tool | Outcome | Server message |", "|---|---|---|---|"]
    for row in result["attacks"]:
        detail = row["detail"].replace("|", "\\|")
        lines.append(f"| {row['scenario']} | `{row['tool']}` | {row['decision']} | {detail} |")
    lines += ["", f"Every call above was written to the JSONL audit log ({result['audit_lines']} lines)."]
    (RESULTS / "permission_matrix.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(main())
