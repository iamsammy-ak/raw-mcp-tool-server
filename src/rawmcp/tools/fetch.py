"""HTTP(S) fetch restricted to an allowlist of domains.

Defences against server-side request forgery (SSRF):

* only ``https`` (``http`` only if the policy says so), no credentials in the URL, default ports;
* the host must match the policy allowlist (exact host or ``*.suffix``);
* every address the host resolves to must be public unless ``allow_private_networks`` is set,
  so an allowlisted name that points at ``127.0.0.1`` or ``169.254.169.254`` is still refused;
* each redirect hop is re-checked against the same rules; environment proxies are ignored;
* the response body is capped at ``max_bytes`` and only text-like content types are returned.

The network layer is injectable (:class:`Fetcher`, :data:`Resolver`), which is how the tests
run without network access.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from email.message import Message
from typing import Protocol
from urllib.parse import urlsplit

from pydantic import Field

from rawmcp.context import ToolContext
from rawmcp.policy import FetchPolicy
from rawmcp.tools.base import PolicyDenied, Tool, ToolError, ToolInput, ToolOutput

_TEXT_TYPES = ("application/json", "application/xml", "application/javascript", "application/x-yaml")
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class FetchResponse:
    """What a :class:`Fetcher` returns."""

    final_url: str
    status: int
    content_type: str
    body: bytes
    truncated: bool


class Fetcher(Protocol):
    """Performs the HTTP request. ``check_redirect`` must be called for every redirect target."""

    def fetch(self, url: str, *, timeout: float, max_bytes: int, max_redirects: int,
              check_redirect: Callable[[str], None]) -> FetchResponse: ...


Resolver = Callable[[str], list[str]]
"""Maps a host name to the IP addresses it resolves to."""


def system_resolver(host: str) -> list[str]:
    """Resolve with the operating system's resolver."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({str(info[4][0]) for info in infos})


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, check: Callable[[str], None], limit: int) -> None:
        self.check = check
        self.limit = limit
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        self.count += 1
        if self.count > self.limit:
            raise PolicyDenied(f"more than {self.limit} redirects")
        self.check(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class UrllibFetcher:
    """Standard-library fetcher that ignores proxy environment variables."""

    def fetch(self, url: str, *, timeout: float, max_bytes: int, max_redirects: int,
              check_redirect: Callable[[str], None]) -> FetchResponse:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             _CheckedRedirects(check_redirect, max_redirects))
        request = urllib.request.Request(url, headers={"User-Agent": "rawmcp-fetch/0.1", "Accept": "text/*, */*"})
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:  # 4xx/5xx still carry a body worth returning
            response = exc
        with response:
            body = response.read(max_bytes + 1)
            return FetchResponse(final_url=response.geturl(), status=response.status,
                                 content_type=response.headers.get("Content-Type", ""),
                                 body=body[:max_bytes], truncated=len(body) > max_bytes)


def host_allowed(host: str, port: int | None, patterns: tuple[str, ...]) -> bool:
    """Match ``host`` (and a non-default ``port``) against exact and ``*.suffix`` patterns."""
    for pattern in patterns:
        pat_host, _, pat_port = pattern.partition(":")
        if port is not None and pat_port != str(port):
            continue
        if port is None and pat_port:
            continue
        if pat_host.startswith("*."):
            if host.endswith(pat_host[1:]) and host != pat_host[2:]:
                return True
        elif host == pat_host:
            return True
    return False


def is_public_address(address: str) -> bool:
    """False for loopback, private, link-local, multicast, reserved and unspecified addresses."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


class FetchUrlInput(ToolInput):
    url: str = Field(min_length=1, max_length=2_048, description="Absolute https:// URL on an allowlisted domain.")
    max_bytes: int = Field(default=50_000, ge=1, le=1_000_000, description="Truncate the body after this many bytes.")


class FetchUrlOutput(ToolOutput):
    url: str
    final_url: str
    status: int
    content_type: str
    bytes: int
    truncated: bool
    text: str


class FetchUrl(Tool):
    name = "fetch_url"
    title = "Fetch URL (allowlisted domains)"
    description = (
        "GET a text resource over HTTPS from a domain on the server's allowlist. Private and "
        "loopback addresses are refused; redirects are re-checked; the body is size-capped."
    )
    input_model = FetchUrlInput
    output_model = FetchUrlOutput
    scopes = frozenset({"net:fetch"})
    open_world = True
    idempotent = True

    def __init__(self, policy: FetchPolicy, fetcher: Fetcher | None = None, resolver: Resolver | None = None) -> None:
        self.policy = policy
        self.fetcher = fetcher or UrllibFetcher()
        self.resolver = resolver or system_resolver

    def check_url(self, url: str) -> None:
        """Raise :class:`PolicyDenied` unless ``url`` satisfies every egress rule."""
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise PolicyDenied(f"invalid URL: {exc}") from None
        allowed_schemes = ("https", "http") if self.policy.allow_http else ("https",)
        if parts.scheme not in allowed_schemes:
            allowed = " or ".join(allowed_schemes)
            raise PolicyDenied(f"scheme {parts.scheme or '(none)'!r} is not allowed; use {allowed}")
        if parts.username is not None or parts.password is not None:
            raise PolicyDenied("URLs with embedded credentials are not allowed")
        host = (parts.hostname or "").rstrip(".")
        if not host:
            raise PolicyDenied("URL has no host")
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise PolicyDenied("host name is not valid IDNA") from None
        if port == _DEFAULT_PORTS[parts.scheme]:
            port = None
        if not host_allowed(host, port, self.policy.allow_domains):
            raise PolicyDenied(f"domain {host!r} is not on the allowlist")
        if self.policy.allow_private_networks:
            return
        try:
            addresses = [host] if _is_ip(host) else self.resolver(host)
        except OSError:
            raise ToolError(f"could not resolve {host!r}") from None
        if not addresses:
            raise ToolError(f"could not resolve {host!r}")
        blocked = [a for a in addresses if not is_public_address(a)]
        if blocked:
            raise PolicyDenied(f"{host!r} resolves to a non-public address ({blocked[0]}); refusing to connect")

    async def run(self, args: FetchUrlInput, ctx: ToolContext) -> FetchUrlOutput:
        await asyncio.to_thread(self.check_url, args.url)
        max_bytes = min(args.max_bytes, self.policy.max_bytes)
        try:
            response = await asyncio.to_thread(
                self.fetcher.fetch, args.url, timeout=self.policy.timeout_s, max_bytes=max_bytes,
                max_redirects=self.policy.max_redirects, check_redirect=self.check_url)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise ToolError(f"request failed: {getattr(exc, 'reason', exc)}") from None
        media_type, charset = _parse_content_type(response.content_type)
        if not (media_type.startswith("text/") or media_type in _TEXT_TYPES
                or media_type.endswith(("+json", "+xml"))):
            raise ToolError(f"content type {media_type or '(none)'!r} is not text; refusing to return it")
        try:
            text = response.body.decode(charset or "utf-8", errors="replace")
        except LookupError:
            text = response.body.decode("utf-8", errors="replace")
        return FetchUrlOutput(url=args.url, final_url=response.final_url, status=response.status,
                              content_type=media_type, bytes=len(response.body), truncated=response.truncated,
                              text=text)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _parse_content_type(value: str) -> tuple[str, str | None]:
    message = Message()
    message["Content-Type"] = value or "application/octet-stream"
    charset = message.get_param("charset")
    return message.get_content_type().lower(), charset if isinstance(charset, str) else None
