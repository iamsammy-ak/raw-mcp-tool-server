"""Regenerate the terminal SVGs in assets/ from a live server process.

usage: PYTHONPATH=src python scripts/render_assets.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any

from rich.console import Console, Group
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rawmcp.client import RawStdioClient, server_command
from rawmcp.demo import _shorten, run_demo, save_svg

ASSETS = Path(__file__).resolve().parents[1] / "assets"
POLICY = "version: 1\nworkspace: ./workspace\nprofiles:\n  reader:\n    scopes: [fs:read, db:read]\n"


def pretty(arrow: str, style: str, message: Any) -> list[Any]:
    view = _shorten(message, keep_meta=True, keep_text=False)
    return [Text(arrow, style=style), JSON.from_data(view, indent=2)]


def eras(path: Path) -> None:
    """Pretty-printed side by side: the legacy handshake vs one self-describing modern request."""
    if hasattr(sys.stdout, "reconfigure"):  # Windows consoles default to a legacy code page
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    console = Console(record=True, width=132, legacy_windows=False)
    with tempfile.TemporaryDirectory(prefix="rawmcp-assets-") as tmp:
        root = Path(tmp)
        (root / "workspace").mkdir()
        (root / "policy.yaml").write_text(POLICY, encoding="utf-8")
        argv, env = server_command(root / "policy.yaml", "reader")
        call = {"name": "calculate", "arguments": {"expression": "6 * 7"}}
        with RawStdioClient(argv, env=env) as client:
            init, _ = client.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                                    "clientInfo": {"name": "legacy-client", "version": "1.0"}},
                                     modern=False)
            client.notify("notifications/initialized")
            legacy_call, _ = client.request("tools/call", call, modern=False)
            legacy = client.transcript[:]
            modern_call, _ = client.request("tools/call", call)
            modern = client.transcript[len(legacy):]
        assert "result" in init and "result" in legacy_call and "result" in modern_call

    def column(messages: list[tuple[str, Any]]) -> Group:
        parts: list[Any] = []
        for direction, message in messages:
            arrow, style = ("→ client", "bold green") if direction == "client" else ("← server", "bold magenta")
            parts += pretty(arrow, style, message)
        return Group(*parts)

    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(
        Panel(column(legacy), border_style="grey50", title_align="left",
              title="[bold]2025-11-25 and earlier[/] · handshake, then calls"),
        Panel(column(modern), border_style="cyan", title_align="left",
              title="[bold]2026-07-28[/] · one self-describing request"),
    )
    console.print(grid)
    console.print(Text("Same server process, same tool call. \"…\" marks text elided for display "
                       "(the JSON-as-text copy of structuredContent, titles, instructions).", style="italic grey62"))
    save_svg(console, str(path), "rawmcp: legacy handshake vs stateless 2026-07-28 request")


def main() -> int:
    ASSETS.mkdir(exist_ok=True)
    status = run_demo(svg_path=str(ASSETS / "demo.svg"))
    eras(ASSETS / "eras.svg")
    return status


if __name__ == "__main__":
    sys.exit(main())
