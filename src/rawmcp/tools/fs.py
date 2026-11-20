"""Filesystem tools. Every path goes through the :class:`~rawmcp.jail.Jail`."""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import os
import stat
from pathlib import Path
from typing import Literal

from pydantic import Field

from rawmcp.context import ToolContext
from rawmcp.jail import Jail, JailError
from rawmcp.tools.base import PolicyDenied, Tool, ToolError, ToolInput, ToolOutput

MAX_READ_BYTES = 1_048_576
MAX_WRITE_BYTES = 1_048_576
MAX_LIST_ENTRIES = 1_000
MAX_SCAN_FILES = 5_000
MAX_SEARCH_FILE_BYTES = 2_000_000
PROGRESS_EVERY = 25


def _resolve(jail: Jail, path: str) -> Path:
    try:
        return jail.resolve(path)
    except JailError as exc:
        raise PolicyDenied(str(exc)) from None


# --------------------------------------------------------------------------- read_file


class ReadFileInput(ToolInput):
    path: str = Field(min_length=1, max_length=1024, description="File path relative to the workspace root.")
    max_bytes: int = Field(default=65_536, ge=1, le=MAX_READ_BYTES,
                           description="Read at most this many bytes; longer files are truncated.")


class ReadFileOutput(ToolOutput):
    path: str
    size_bytes: int
    truncated: bool
    sha256: str = Field(description="SHA-256 of the full file.")
    content: str


class ReadFile(Tool):
    name = "read_file"
    title = "Read file"
    description = "Read a UTF-8 text file inside the workspace. Binary files are refused."
    input_model = ReadFileInput
    output_model = ReadFileOutput
    scopes = frozenset({"fs:read"})

    def __init__(self, jail: Jail) -> None:
        self.jail = jail

    async def run(self, args: ReadFileInput, ctx: ToolContext) -> ReadFileOutput:
        target = _resolve(self.jail, args.path)
        return await asyncio.to_thread(self._read, target, args.max_bytes)

    def _read(self, target: Path, max_bytes: int) -> ReadFileOutput:
        shown = self.jail.display(target)
        if not target.exists():
            raise ToolError(f"file not found: {shown}")
        if not target.is_file():
            raise ToolError(f"not a regular file: {shown}")
        digest = hashlib.sha256()
        head = b""
        size = 0
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65_536), b""):
                digest.update(chunk)
                if len(head) < max_bytes + 1:
                    head += chunk[: max_bytes + 1 - len(head)]
                size += len(chunk)
        if b"\x00" in head[:8192]:
            raise ToolError(f"{shown} looks like a binary file; only text files can be read")
        truncated = size > max_bytes
        text = head[:max_bytes].decode("utf-8", errors="replace")
        return ReadFileOutput(path=shown, size_bytes=size, truncated=truncated, sha256=digest.hexdigest(),
                              content=text)


# --------------------------------------------------------------------------- list_dir


class ListDirInput(ToolInput):
    path: str = Field(default=".", min_length=1, max_length=1024,
                      description="Directory relative to the workspace root.")
    include_hidden: bool = Field(default=False, description="Include entries whose name starts with a dot.")


class DirEntry(ToolOutput):
    name: str
    type: Literal["file", "dir", "symlink", "other"]
    size_bytes: int | None = None


class ListDirOutput(ToolOutput):
    path: str
    entries: list[DirEntry]
    truncated: bool


class ListDir(Tool):
    name = "list_dir"
    title = "List directory"
    description = "List a directory inside the workspace. Symlinks are reported, never followed."
    input_model = ListDirInput
    output_model = ListDirOutput
    scopes = frozenset({"fs:read"})

    def __init__(self, jail: Jail) -> None:
        self.jail = jail

    async def run(self, args: ListDirInput, ctx: ToolContext) -> ListDirOutput:
        target = _resolve(self.jail, args.path)
        return await asyncio.to_thread(self._list, target, args.include_hidden)

    def _list(self, target: Path, include_hidden: bool) -> ListDirOutput:
        shown = self.jail.display(target)
        if not target.is_dir():
            raise ToolError(f"not a directory: {shown}")
        entries: list[DirEntry] = []
        truncated = False
        with os.scandir(target) as it:
            for entry in sorted(it, key=lambda e: e.name):
                if not include_hidden and entry.name.startswith("."):
                    continue
                if len(entries) >= MAX_LIST_ENTRIES:
                    truncated = True
                    break
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    entries.append(DirEntry(name=entry.name, type="other"))
                    continue
                junction = getattr(entry, "is_junction", None)  # Windows junctions, Python 3.12+
                if stat.S_ISLNK(info.st_mode) or (junction is not None and junction()):
                    entries.append(DirEntry(name=entry.name, type="symlink"))
                elif stat.S_ISDIR(info.st_mode):
                    entries.append(DirEntry(name=entry.name, type="dir"))
                elif stat.S_ISREG(info.st_mode):
                    entries.append(DirEntry(name=entry.name, type="file", size_bytes=info.st_size))
                else:
                    entries.append(DirEntry(name=entry.name, type="other"))
        return ListDirOutput(path=shown, entries=entries, truncated=truncated)


# --------------------------------------------------------------------------- search_files


class SearchFilesInput(ToolInput):
    query: str = Field(min_length=1, max_length=200, description="Literal text to look for (not a regex).")
    path: str = Field(default=".", min_length=1, max_length=1024, description="Directory to search under.")
    glob: str = Field(default="*", min_length=1, max_length=100,
                      description="Only search files whose name matches this glob, e.g. '*.md'.")
    case_sensitive: bool = False
    max_results: int = Field(default=50, ge=1, le=500)


class SearchMatch(ToolOutput):
    path: str
    line: int
    text: str


class SearchFilesOutput(ToolOutput):
    matches: list[SearchMatch]
    files_scanned: int
    truncated: bool


class SearchFiles(Tool):
    name = "search_files"
    title = "Search files"
    description = (
        "Find lines containing a literal string in text files under a workspace directory. "
        "Sends progress notifications when the request carries a progressToken."
    )
    input_model = SearchFilesInput
    output_model = SearchFilesOutput
    scopes = frozenset({"fs:read"})

    def __init__(self, jail: Jail) -> None:
        self.jail = jail

    async def run(self, args: SearchFilesInput, ctx: ToolContext) -> SearchFilesOutput:
        root = _resolve(self.jail, args.path)
        if not root.is_dir():
            raise ToolError(f"not a directory: {self.jail.display(root)}")
        files = await asyncio.to_thread(self._candidates, root, args.glob)
        matches: list[SearchMatch] = []
        scanned = 0
        # Scan in batches so progress is sent from the event loop between batches: notifications
        # stay ordered before the final response and cancellation takes effect between batches.
        for start in range(0, len(files), PROGRESS_EVERY):
            await ctx.progress(start, len(files), f"scanned {start} of {len(files)} files")
            batch = files[start : start + PROGRESS_EVERY]
            scanned += await asyncio.to_thread(self._scan, batch, args, matches)
            if len(matches) >= args.max_results:
                return SearchFilesOutput(matches=matches[: args.max_results], files_scanned=scanned, truncated=True)
        await ctx.progress(len(files), len(files), f"scanned {len(files)} files")
        return SearchFilesOutput(matches=matches, files_scanned=scanned, truncated=False)

    def _candidates(self, root: Path, pattern: str) -> list[Path]:
        found: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
            for filename in sorted(filenames):
                if filename.startswith(".") or not fnmatch.fnmatch(filename, pattern):
                    continue
                path = Path(dirpath) / filename
                if path.is_symlink() or not self.jail.contains(Path(os.path.realpath(path))):
                    continue
                found.append(path)
                if len(found) >= MAX_SCAN_FILES:
                    return found
        return found

    def _scan(self, files: list[Path], args: SearchFilesInput, matches: list[SearchMatch]) -> int:
        """Append matches from ``files`` (stopping at ``max_results``); return how many files were read."""
        needle = args.query if args.case_sensitive else args.query.casefold()
        scanned = 0
        for path in files:
            try:
                if path.stat().st_size > MAX_SEARCH_FILE_BYTES:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            scanned += 1
            if b"\x00" in data[:8192]:
                continue
            for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), start=1):
                haystack = line if args.case_sensitive else line.casefold()
                if needle in haystack:
                    matches.append(SearchMatch(path=self.jail.display(path), line=number, text=line.strip()[:300]))
                    if len(matches) >= args.max_results:
                        return scanned
        return scanned


# --------------------------------------------------------------------------- write_file


class WriteFileInput(ToolInput):
    path: str = Field(min_length=1, max_length=1024, description="File path relative to the workspace root.")
    content: str = Field(max_length=MAX_WRITE_BYTES, description="UTF-8 text to write.")
    mode: Literal["create", "overwrite", "append"] = Field(
        default="create", description="'create' fails if the file exists; 'overwrite' replaces it; 'append' adds.")


class WriteFileOutput(ToolOutput):
    path: str
    bytes_written: int
    created: bool
    sha256: str


class WriteFile(Tool):
    name = "write_file"
    title = "Write file"
    description = "Create, overwrite or append to a UTF-8 text file inside the workspace. Never follows symlinks."
    input_model = WriteFileInput
    output_model = WriteFileOutput
    scopes = frozenset({"fs:write"})
    read_only = False
    destructive = True
    idempotent = False

    def __init__(self, jail: Jail) -> None:
        self.jail = jail

    async def run(self, args: WriteFileInput, ctx: ToolContext) -> WriteFileOutput:
        lexical = self.jail.root / args.path
        target = _resolve(self.jail, args.path)
        return await asyncio.to_thread(self._write, lexical, target, args)

    def _write(self, lexical: Path, target: Path, args: WriteFileInput) -> WriteFileOutput:
        shown = self.jail.display(target)
        if lexical.is_symlink():
            raise PolicyDenied(f"refusing to write through a symlink: {args.path}")
        if not target.parent.is_dir():
            raise ToolError(f"parent directory does not exist: {self.jail.display(target.parent)}")
        if target.exists() and not target.is_file():
            raise ToolError(f"not a regular file: {shown}")
        existed = target.exists()
        if args.mode == "create" and existed:
            raise ToolError(f"{shown} already exists; use mode 'overwrite' or 'append'")
        data = args.content.encode("utf-8")
        if len(data) > MAX_WRITE_BYTES:
            raise ToolError(f"content is larger than {MAX_WRITE_BYTES} bytes once encoded")
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        flags |= {"create": os.O_EXCL, "overwrite": os.O_TRUNC, "append": os.O_APPEND}[args.mode]
        try:
            fd = os.open(target, flags, 0o644)
        except FileExistsError:
            raise ToolError(f"{shown} already exists; use mode 'overwrite' or 'append'") from None
        except OSError as exc:
            raise ToolError(f"cannot open {shown} for writing: {exc.strerror}") from None
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        return WriteFileOutput(path=shown, bytes_written=len(data), created=not existed, sha256=digest)
