"""Command-line interface: ``rawmcp serve | demo | tools | hash-token``."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from rawmcp import __version__
from rawmcp.context import Principal
from rawmcp.policy import Policy, default_policy, hash_token, load_policy
from rawmcp.server import McpServer, ServerOptions

log = logging.getLogger("rawmcp")

DEFAULT_PORT = 8706


def resolve_policy(path: str | None) -> tuple[Policy, Path | None]:
    """``--policy``, else ``$RAWMCP_POLICY``, else the built-in read-only policy for the current directory."""
    chosen = path or os.environ.get("RAWMCP_POLICY")
    if chosen:
        return load_policy(chosen), Path(chosen)
    return default_policy(Path.cwd()), None


def stdio_principal(policy: Policy, profile: str | None) -> Principal:
    """Pick the stdio caller's profile: ``--profile``, ``$RAWMCP_TOKEN``, the policy default, else nobody."""
    if profile is not None:
        if policy.profile(profile) is None:
            raise SystemExit(f"rawmcp: unknown profile {profile!r} (defined: {', '.join(policy.profiles) or 'none'})")
        return Principal(profile, "stdio:--profile")
    token = os.environ.get("RAWMCP_TOKEN")
    if token:
        matched = policy.authenticate(token)
        if matched is None:
            log.warning("RAWMCP_TOKEN does not match any profile; every call will be denied")
        return Principal(matched, f"stdio:token#{hash_token(token)[:8]}")
    if policy.stdio_profile:
        return Principal(policy.stdio_profile, "stdio:default")
    return Principal(None, "stdio:anonymous")


async def _watch_policy(server: McpServer, path: Path, interval_s: float = 2.0) -> None:
    """Reload the policy when its file changes; a broken edit is logged and ignored."""
    last = path.stat().st_mtime_ns
    while True:
        await asyncio.sleep(interval_s)
        try:
            current = path.stat().st_mtime_ns
            if current == last:
                continue
            last = current
            policy = load_policy(path)
        except Exception as exc:  # keep serving with the previous policy
            log.error("policy reload failed, keeping the previous policy: %s", exc)
            continue
        log.info("policy file changed; reloaded")
        await server.update_policy(policy)


async def _serve_stdio(server: McpServer, principal: Principal, policy_path: Path | None, watch: bool) -> None:
    from rawmcp.transports.stdio import serve_stdio

    watcher = asyncio.ensure_future(_watch_policy(server, policy_path)) if (watch and policy_path) else None
    try:
        await serve_stdio(server, principal)
    finally:
        if watcher is not None:
            watcher.cancel()


def cmd_serve(args: argparse.Namespace) -> int:
    policy, policy_path = resolve_policy(args.policy)
    server = McpServer(policy, options=ServerOptions(page_size=args.page_size))
    if args.transport == "stdio":
        principal = stdio_principal(policy, args.profile)
        asyncio.run(_serve_stdio(server, principal, policy_path, not args.no_watch))
        return 0
    try:
        from rawmcp.transports.http import run_http
    except ImportError:
        print("rawmcp: the HTTP transport needs the 'http' extra: pip install 'rawmcp[http]'", file=sys.stderr)
        return 2
    run_http(server, host=args.host, port=args.port, allowed_origins=args.allowed_origin)
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    policy, _ = resolve_policy(args.policy)
    server = McpServer(policy)
    profile = policy.profile(args.profile) if args.profile else None
    print(f"{'tool':<14} {'scopes':<14} {'allowed for ' + (args.profile or '-'):<20} title")
    for tool in server.all_tools():
        name = tool.name
        scopes = ",".join(sorted(tool.scopes)) or "-"
        allowed = "-" if profile is None else ("yes" if tool.scopes <= profile.scopes else "no")
        print(f"{name:<14} {scopes:<14} {allowed:<20} {tool.title}")
    return 0


def cmd_hash_token(args: argparse.Namespace) -> int:
    print(hash_token(args.token))
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from rawmcp.demo import run_demo

    return run_demo(svg_path=args.svg)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rawmcp", description="MCP tool server built on raw JSON-RPC 2.0.")
    parser.add_argument("--version", action="version", version=f"rawmcp {__version__}")
    parser.add_argument("--log-level", default=os.environ.get("RAWMCP_LOG_LEVEL", "WARNING"),
                        help="stderr log level (default WARNING)")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the server (stdio by default)")
    serve.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    serve.add_argument("--policy", help="YAML policy file (default: $RAWMCP_POLICY or read-only built-in)")
    serve.add_argument("--profile", help="stdio only: profile to act as (else $RAWMCP_TOKEN or the policy default)")
    serve.add_argument("--host", default="127.0.0.1", help="HTTP bind address (default 127.0.0.1)")
    serve.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"HTTP port (default {DEFAULT_PORT})")
    serve.add_argument("--allowed-origin", action="append", default=[],
                       help="extra browser Origin to accept on HTTP (repeatable)")
    serve.add_argument("--page-size", type=int, default=50, help="tools/list page size")
    serve.add_argument("--no-watch", action="store_true", help="do not reload the policy file when it changes")
    serve.set_defaults(func=cmd_serve)

    tools = sub.add_parser("tools", help="list tools, their scopes and whether a profile may call them")
    tools.add_argument("--policy")
    tools.add_argument("--profile")
    tools.set_defaults(func=cmd_tools)

    token = sub.add_parser("hash-token", help="print the SHA-256 digest to put in a policy's token_sha256")
    token.add_argument("token")
    token.set_defaults(func=cmd_hash_token)

    demo = sub.add_parser("demo", help="run a scripted raw JSON-RPC session against a real stdio server")
    demo.add_argument("--svg", help="also save the session as a terminal SVG")
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=args.log_level.upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    status: int = args.func(args)
    return status
