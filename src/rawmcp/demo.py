"""``rawmcp demo``: a scripted raw JSON-RPC session against a real stdio server process.

Everything runs offline in a temporary directory: a small workspace, a policy with an
``analyst`` profile (read files, query the database, run sandboxed Python; no file writes) and
the server itself as a subprocess. Each exchange is printed as the JSON that crossed the pipe.
"""

from __future__ import annotations

import copy
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from rawmcp.client import RawStdioClient, server_command
from rawmcp.versions import META_SUBSCRIPTION_ID

DEMO_POLICY = """\
version: 1
workspace: ./workspace
audit_log: ./audit.jsonl
sandbox: {timeout_s: 5, memory_mb: 256, max_output_bytes: 8192}
profiles:
  analyst:
    description: Read files, query the sample database and run sandboxed Python. No writes.
    scopes: [fs:read, db:read, exec:python]
    rate_limits: {"*": 120/minute, run_python: 10/minute}
"""

DEMO_FILES = {
    "notes/meeting.md": "# Supplier review (synthetic)\n- Lead time slipped from 4 to 6 days.\n",
    "notes/todo.txt": "check revenue by category\ndraft the carrier risk summary\n",
}

_ELIDED = "…"


_ELIDED_KEYS = {"inputSchema", "outputSchema", "annotations", "description", "instructions", "title"}


def _shorten(value: Any, *, keep_meta: bool, keep_text: bool = True) -> Any:
    """Copy of a message trimmed for display: schemas, prose and repeated protocol ``_meta`` become "…".

    With ``keep_text=False`` the text block that merely repeats ``structuredContent`` is elided too.
    """

    def walk(node: Any) -> Any:
        if isinstance(node, dict) and not keep_text and "structuredContent" in node:
            node = {**node, "content": [{"type": "text", "text": "… (structuredContent as JSON text)"}]}
        if isinstance(node, dict):
            out = {}
            for key, item in node.items():
                protocol_meta = key == "_meta" and isinstance(item, dict) and any(
                    k.startswith("io.modelcontextprotocol/") and k != META_SUBSCRIPTION_ID for k in item)
                if key in _ELIDED_KEYS and isinstance(item, (dict, str)) or (protocol_meta and not keep_meta):
                    out[key] = _ELIDED
                else:
                    out[key] = walk(item)
            return out
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return walk(copy.deepcopy(value))


def save_svg(console: Any, path: str, title: str) -> None:
    """Save a recorded Rich console as SVG without the renderer's advertising comment."""
    console.save_svg(path, title=title)
    svg = Path(path).read_text(encoding="utf-8")
    Path(path).write_text(re.sub(r"\s*<!--[^>]*textualize\.io[^>]*-->", "", svg), encoding="utf-8")


def run_demo(svg_path: str | None = None) -> int:
    """Run the scripted session; optionally save the terminal output as an SVG."""
    try:
        from rich.console import Console
        from rich.json import JSON
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError:
        print("rawmcp demo needs the 'demo' extra: pip install 'rawmcp[demo]'")
        return 2

    if hasattr(sys.stdout, "reconfigure"):  # Windows consoles default to a legacy code page
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    console = Console(record=svg_path is not None, width=100, legacy_windows=False)
    with tempfile.TemporaryDirectory(prefix="rawmcp-demo-") as tmp:
        root = Path(tmp)
        for rel, text in DEMO_FILES.items():
            path = root / "workspace" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        (root / "policy.yaml").write_text(DEMO_POLICY, encoding="utf-8")
        argv, env = server_command(root / "policy.yaml", "analyst", "--page-size", "4")

        console.print(Panel.fit(
            Text.assemble(("rawmcp", "bold cyan"), " · raw JSON-RPC 2.0 over stdio · profile ",
                          ("analyst", "bold"), " (fs:read, db:read, exec:python)"),
            border_style="cyan"))

        first = {"request": True, "result": True, "text": True}

        def line(arrow: str, style: str, message: Any, kind: str) -> Text:
            if isinstance(message, str):
                return Text.assemble((arrow, style), (message, "red"))
            structured = "structuredContent" in json.dumps(message)
            view = _shorten(message, keep_meta=first[kind], keep_text=first["text"] or not structured)
            first[kind] = False
            if structured:
                first["text"] = False
            return Text.assemble((arrow, style), JSON.from_data(view, indent=None).text)

        def show(title: str, sent: Any, received: list[Any], note: str = "") -> None:
            console.rule(Text(title, style="bold"), align="left", style="grey50")
            console.print(line("→ ", "bold green", sent, "request"))
            for message in received:
                arrow = "⇠ " if isinstance(message, dict) and "method" in message else "← "
                console.print(line(arrow, "bold magenta", message, "result"))
            if note:
                console.print(Text("  " + note, style="italic grey62"))

        with RawStdioClient(argv, env=env) as client:
            def exchange(title: str, method: str, params: dict[str, Any] | None = None, note: str = "",
                         modern: bool = True, **meta: Any) -> dict[str, Any]:
                response, notes = client.request(method, params, modern=modern, **meta)
                show(title, client.transcript[-2 - len(notes)][1], [*notes, response], note)
                return response

            exchange("1 · discovery, no handshake (2026-07-28)", "server/discover",
                     note="Every modern request carries its protocol version and capabilities in _meta.")
            exchange("2 · tools/list is filtered by scope and paginated", "tools/list",
                     note="write_file and fetch_url need scopes this profile lacks, so they are not listed.")
            exchange("3 · a tool call returns text + schema-checked structuredContent", "tools/call",
                     {"name": "calculate", "arguments": {"expression": "2 * (3 + 4) ** 2"}})
            exchange("4 · path traversal is a tool error, not a crash", "tools/call",
                     {"name": "read_file", "arguments": {"path": "../policy.yaml"}})
            exchange("5 · missing scope: write_file needs fs:write", "tools/call",
                     {"name": "write_file", "arguments": {"path": "notes/x.txt", "content": "hi"}})
            exchange("6 · strict schema: 42 is not a string (SEP-1303: a tool error the model can fix)",
                     "tools/call", {"name": "calculate", "arguments": {"expression": 42}})
            exchange("7 · sandboxed Python with progress notifications", "tools/call",
                     {"name": "run_python", "arguments": {"code": "import statistics\n"
                                                          "print(statistics.mean([3, 5, 10]))"}},
                     progressToken="run-1")
            bad = '{"jsonrpc":"2.0","id":99,"method":'
            client.send_raw(bad.encode())
            show("8 · malformed JSON gets -32700 and the server keeps going", bad, [client.recv()])
            exchange("9 · legacy client: initialize handshake (2025-06-18)", "initialize",
                     {"protocolVersion": "2025-06-18", "capabilities": {},
                      "clientInfo": {"name": "old-client", "version": "1.0"}}, modern=False,
                     note="Then notifications/initialized; results carry no resultType or cache hints.")
            client.notify("notifications/initialized")

        table = Table(title="audit.jsonl (arguments are stored as SHA-256 only)", title_justify="left",
                      header_style="bold")
        for column in ("tool", "decision", "is_error", "args_sha256", "ms"):
            table.add_column(column)
        for raw in (root / "audit.jsonl").read_text(encoding="utf-8").splitlines():
            record = json.loads(raw)
            style = {"allow": "green", "deny": "red", "invalid": "yellow"}.get(record["decision"], "")
            table.add_row(record["tool"], f"[{style}]{record['decision']}[/]", str(record["is_error"]),
                          record["args_sha256"][:12] + "…", f"{record['duration_ms']:.1f}")
        console.print(table)
    if svg_path:
        save_svg(console, svg_path, "rawmcp demo: raw JSON-RPC over stdio")
    return 0
