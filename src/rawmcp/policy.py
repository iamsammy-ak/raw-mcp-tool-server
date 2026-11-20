"""Permission policy: who may call which tool, where, and how often.

The policy is a YAML file validated by strict Pydantic models. It maps client *profiles* to
*scopes*; tools declare the scopes they need, and a call is allowed only when the caller's
profile grants all of them. Anything not granted is denied: an unknown token or profile gets
no scopes at all.

Example::

    version: 1
    workspace: ./workspace          # filesystem jail root, relative to this file
    audit_log: ./audit.jsonl
    fetch:
      allow_domains: [example.com, "*.python.org"]
    profiles:
      reader:
        scopes: [fs:read, db:read]
        token_sha256: [<sha256 of the bearer token>]
        rate_limits: {"*": 120/minute}
"""

from __future__ import annotations

import hashlib
import hmac
import re
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Scope = Literal["fs:read", "fs:write", "net:fetch", "exec:python", "db:read"]
ALL_SCOPES: tuple[str, ...] = ("fs:read", "fs:write", "net:fetch", "exec:python", "db:read")

_RATE_RE = re.compile(r"^\s*(\d+)\s*/\s*(second|minute|hour)\s*$")
_PERIODS = {"second": 1.0, "minute": 60.0, "hour": 3600.0}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9-]+\.)*[a-z0-9-]+(:\d{1,5})?$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RateLimit(_Strict):
    """``calls`` per ``period_s`` seconds, enforced as a token bucket."""

    calls: int = Field(ge=1)
    period_s: float = Field(gt=0)

    @classmethod
    def parse(cls, text: str) -> RateLimit:
        """Parse ``"10/minute"``-style strings."""
        match = _RATE_RE.match(text)
        if not match:
            raise ValueError(f"rate limit {text!r} must look like '10/minute' (second, minute or hour)")
        return cls(calls=int(match.group(1)), period_s=_PERIODS[match.group(2)])

    def __str__(self) -> str:
        unit = {1.0: "second", 60.0: "minute", 3600.0: "hour"}.get(self.period_s)
        return f"{self.calls}/{unit}" if unit else f"{self.calls}/{self.period_s:g}s"


class Profile(_Strict):
    """A named set of scopes and limits that a client authenticates into."""

    description: str = ""
    scopes: frozenset[Scope] = frozenset()
    token_sha256: tuple[str, ...] = ()
    rate_limits: dict[str, RateLimit] = Field(default_factory=dict)

    @field_validator("token_sha256", mode="before")
    @classmethod
    def _hashes(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = [value]
        for item in value or ():
            if not isinstance(item, str) or not _SHA256_RE.match(item):
                raise ValueError("token_sha256 entries must be lowercase hex SHA-256 digests (64 characters)")
        return value

    @field_validator("rate_limits", mode="before")
    @classmethod
    def _rates(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        return {tool: RateLimit.parse(spec) if isinstance(spec, str) else spec for tool, spec in value.items()}

    def rate_limit_for(self, tool: str) -> RateLimit | None:
        """The tool-specific limit, else the ``"*"`` default, else none."""
        return self.rate_limits.get(tool) or self.rate_limits.get("*")


class FetchPolicy(_Strict):
    """Network egress rules for ``fetch_url``."""

    allow_domains: tuple[str, ...] = ()
    """Exact hosts (``example.com``) or suffix wildcards (``*.example.com``); optional ``:port``."""
    allow_http: bool = False
    allow_private_networks: bool = False
    max_bytes: int = Field(default=200_000, ge=1, le=10_000_000)
    timeout_s: float = Field(default=10.0, gt=0, le=120)
    max_redirects: int = Field(default=3, ge=0, le=10)

    @field_validator("allow_domains", mode="before")
    @classmethod
    def _domains(cls, value: Any) -> Any:
        out = []
        for item in value or ():
            text = str(item).strip().lower()
            if not _DOMAIN_RE.match(text):
                raise ValueError(f"invalid domain pattern {item!r}")
            out.append(text)
        return out


class SandboxPolicy(_Strict):
    """Limits applied to every ``run_python`` subprocess."""

    timeout_s: float = Field(default=5.0, gt=0, le=300)
    max_timeout_s: float = Field(default=30.0, gt=0, le=300)
    memory_mb: int = Field(default=256, ge=32, le=16_384)
    cpu_s: int = Field(default=10, ge=1, le=3600)
    max_open_files: int = Field(default=64, ge=8, le=4096)
    max_file_bytes: int = Field(default=1_048_576, ge=0)
    max_output_bytes: int = Field(default=65_536, ge=1_024, le=10_000_000)
    max_concurrent: int = Field(default=2, ge=1, le=64)


class Policy(_Strict):
    """The whole policy file."""

    version: Literal[1] = 1
    workspace: Path
    """Filesystem jail root. Every file tool resolves paths inside it."""
    audit_log: Path | None = None
    database: Path | None = None
    """SQLite database for ``sqlite_query``; defaults to the bundled synthetic sample."""
    stdio_profile: str | None = None
    """Profile used on stdio when neither ``--profile`` nor ``RAWMCP_TOKEN`` selects one."""
    fetch: FetchPolicy = Field(default_factory=FetchPolicy)
    sandbox: SandboxPolicy = Field(default_factory=SandboxPolicy)
    profiles: dict[str, Profile] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_refs(self) -> Policy:
        if self.stdio_profile is not None and self.stdio_profile not in self.profiles:
            raise ValueError(f"stdio_profile {self.stdio_profile!r} is not a defined profile")
        seen: dict[str, str] = {}
        for name, profile in self.profiles.items():
            for digest in profile.token_sha256:
                if digest in seen:
                    raise ValueError(f"token hash reused by profiles {seen[digest]!r} and {name!r}")
                seen[digest] = name
        return self

    def authenticate(self, token: str) -> str | None:
        """Return the profile whose token hash matches ``token``, comparing in constant time."""
        digest = hash_token(token)
        match: str | None = None
        for name, profile in self.profiles.items():
            for candidate in profile.token_sha256:
                if hmac.compare_digest(candidate, digest):
                    match = name
        return match

    def profile(self, name: str | None) -> Profile | None:
        """Look up a profile by name; ``None`` for unknown names (deny by default)."""
        return self.profiles.get(name) if name else None


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a bearer token. Policies store digests, never raw tokens."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _resolve(base: Path, value: Any) -> Any:
    if value is None:
        return None
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else (base / path)


def policy_from_dict(data: dict[str, Any], base_dir: Path) -> Policy:
    """Validate a policy mapping, resolving relative paths against ``base_dir``."""
    if not isinstance(data, dict):
        raise ValueError("policy must be a mapping")
    data = dict(data)
    for key in ("workspace", "audit_log", "database"):
        if key in data:
            data[key] = _resolve(base_dir, data[key])
    return Policy.model_validate(data)


def load_policy(path: str | Path) -> Policy:
    """Load and validate a YAML policy file."""
    file = Path(path).expanduser()
    with file.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return policy_from_dict(data, file.resolve().parent)


def default_policy(workspace: Path) -> Policy:
    """The built-in policy used when no file is given: read-only access to ``workspace``.

    Writing, network access and code execution need an explicit policy file.
    """
    text = resources.files("rawmcp").joinpath("data/default-policy.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    data["workspace"] = str(workspace)
    return policy_from_dict(data, workspace)
