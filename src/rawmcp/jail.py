"""Filesystem jail: every path a tool touches must resolve inside one root directory.

Checks, in order:

1. the path is a non-empty relative path with no NUL bytes, drive letter or UNC prefix;
2. it is joined to the root and fully resolved with ``os.path.realpath``, which follows
   every symlink (and Windows junction) along the way;
3. the resolved path must still be the root or a descendant of it.

Because resolution happens *after* joining, ``../`` sequences, absolute symlink targets and
symlinked parent directories are all caught by the same containment test. Paths shown to
clients are always relative to the root, so the server never discloses where it lives.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath


class JailError(Exception):
    """A path was rejected by the jail. The message is safe to show to clients."""


_DRIVE_RE = re.compile(r"^[A-Za-z]:")
MAX_PATH_CHARS = 1024


class Jail:
    """Resolves client-supplied paths inside ``root``."""

    def __init__(self, root: Path) -> None:
        resolved = Path(os.path.realpath(root))
        if not resolved.is_dir():
            raise JailError(f"workspace {root} is not a directory")
        self.root = resolved

    def resolve(self, user_path: str) -> Path:
        """Return the real, absolute path for ``user_path`` or raise ``JailError``."""
        if not isinstance(user_path, str) or user_path == "":
            raise JailError("path must be a non-empty string")
        if len(user_path) > MAX_PATH_CHARS:
            raise JailError(f"path is longer than {MAX_PATH_CHARS} characters")
        if "\x00" in user_path:
            raise JailError("path contains a NUL byte")
        if (
            user_path.startswith(("/", "\\", "~"))
            or _DRIVE_RE.match(user_path)
            or PurePosixPath(user_path).is_absolute()
            or PureWindowsPath(user_path).is_absolute()
            or PureWindowsPath(user_path).drive
        ):
            raise JailError("absolute paths are not allowed; use a path relative to the workspace")
        candidate = Path(os.path.realpath(self.root / user_path))
        if not self.contains(candidate):
            raise JailError(f"path {user_path!r} resolves outside the workspace")
        return candidate

    def contains(self, path: Path) -> bool:
        """Whether an already-resolved path is the root or inside it."""
        try:
            path.relative_to(self.root)
        except ValueError:
            return False
        return True

    def display(self, path: Path) -> str:
        """Root-relative POSIX-style path for messages and results (``.`` for the root)."""
        try:
            rel = path.relative_to(self.root)
        except ValueError:
            return "<outside workspace>"
        text = rel.as_posix()
        return text if text else "."
