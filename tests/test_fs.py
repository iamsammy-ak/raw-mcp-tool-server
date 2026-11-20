"""Filesystem jail and the file tools."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from rawmcp.jail import Jail, JailError

from .conftest import Harness, text_of


def _symlink(target: Path, link: Path, *, directory: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs extra privileges on this platform")


@pytest.mark.parametrize(
    "path",
    ["../secret.txt", "notes/../../secret.txt", "/etc/passwd", "\\\\server\\share\\x", "C:/Windows/win.ini",
     "c:relative", "~/x", "notes/\x00.txt", "", "a" * 2000],
)
def test_jail_rejects_escapes(workspace: Path, path: str) -> None:
    with pytest.raises(JailError):
        Jail(workspace).resolve(path)


def test_jail_allows_dotdot_that_stays_inside(workspace: Path) -> None:
    jail = Jail(workspace)
    resolved = jail.resolve("notes/../hello.txt")
    assert resolved == jail.root / "hello.txt"
    assert jail.display(resolved) == "hello.txt"
    assert jail.display(jail.root) == "."


def test_jail_blocks_symlink_pointing_outside(workspace: Path, tmp_path: Path) -> None:
    _symlink(tmp_path / "secret.txt", workspace / "innocent.txt")
    with pytest.raises(JailError):
        Jail(workspace).resolve("innocent.txt")


def test_jail_blocks_symlinked_directory_pointing_outside(workspace: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside_dir"
    outside.mkdir()
    (outside / "data.txt").write_text("x", encoding="utf-8")
    _symlink(outside, workspace / "linkdir", directory=True)
    with pytest.raises(JailError):
        Jail(workspace).resolve("linkdir/data.txt")


async def test_read_file_returns_content_and_hash(harness) -> None:
    h: Harness = harness()
    result = (await h.call("read_file", {"path": "notes/todo.txt"}))["result"]["structuredContent"]
    assert result["content"].startswith("buy coffee") and result["path"] == "notes/todo.txt"
    assert len(result["sha256"]) == 64 and result["truncated"] is False


async def test_read_file_truncates_and_refuses_binary(harness) -> None:
    h: Harness = harness()
    small = (await h.call("read_file", {"path": "hello.txt", "max_bytes": 5}))["result"]["structuredContent"]
    assert small["content"] == "hello" and small["truncated"] is True and small["size_bytes"] == 12
    binary = await h.call("read_file", {"path": "blob.bin"})
    assert binary["result"]["isError"] is True and "binary" in text_of(binary)
    missing = await h.call("read_file", {"path": "nope.txt"})
    assert missing["result"]["isError"] is True and "not found" in text_of(missing)


async def test_errors_never_leak_the_server_path(harness, workspace: Path) -> None:
    h: Harness = harness()
    for args in ({"path": "../secret.txt"}, {"path": "nope.txt"}, {"path": "notes"}):
        message = text_of(await h.call("read_file", args))
        assert str(workspace) not in message and str(workspace.parent) not in message


async def test_list_dir_hides_dotfiles_by_default(harness, workspace: Path) -> None:
    (workspace / ".hidden").write_text("x", encoding="utf-8")
    h: Harness = harness()
    entries = (await h.call("list_dir", {}))["result"]["structuredContent"]["entries"]
    names = [e["name"] for e in entries]
    assert names == sorted(names) and ".hidden" not in names
    assert {"name": "notes", "type": "dir", "size_bytes": None} in entries
    shown = (await h.call("list_dir", {"include_hidden": True}))["result"]["structuredContent"]["entries"]
    assert ".hidden" in [e["name"] for e in shown]


async def test_search_files_reports_progress_in_order(harness, workspace: Path) -> None:
    for i in range(60):
        (workspace / "notes" / f"n{i:02d}.txt").write_text(f"line {i}\nCARRIER {i}\n", encoding="utf-8")
    h: Harness = harness()
    response = await h.call("search_files", {"query": "carrier", "max_results": 500}, progressToken="p1")
    result = response["result"]["structuredContent"]
    assert len(result["matches"]) == 62 and result["truncated"] is False
    progress = [m["params"] for m in h.notifications("notifications/progress")]
    values = [p["progress"] for p in progress]
    assert values == sorted(values) and len(set(values)) == len(values)  # strictly increasing
    assert all(p["progressToken"] == "p1" for p in progress)
    assert progress[-1]["progress"] == progress[-1]["total"]
    response_index = h.outbox.index(response)
    assert all(h.outbox.index(m) < response_index for m in h.notifications("notifications/progress"))


async def test_search_files_case_and_glob(harness) -> None:
    h: Harness = harness()
    sensitive = (await h.call("search_files", {"query": "Carrier", "case_sensitive": True}))["result"]
    assert [m["path"] for m in sensitive["structuredContent"]["matches"]] == ["notes/todo.txt"]
    md_only = (await h.call("search_files", {"query": "carrier", "glob": "*.md"}))["result"]["structuredContent"]
    assert [m["path"] for m in md_only["matches"]] == ["notes/plan.md"]


async def test_write_file_modes(harness, workspace: Path) -> None:
    h: Harness = harness("maintainer")
    created = (await h.call("write_file", {"path": "notes/new.txt", "content": "one\n"}))["result"]
    assert created["structuredContent"]["created"] is True
    again = await h.call("write_file", {"path": "notes/new.txt", "content": "two\n"})
    assert again["result"]["isError"] is True and "already exists" in text_of(again)
    await h.call("write_file", {"path": "notes/new.txt", "content": "two\n", "mode": "append"})
    assert (workspace / "notes" / "new.txt").read_text(encoding="utf-8") == "one\ntwo\n"
    await h.call("write_file", {"path": "notes/new.txt", "content": "three\n", "mode": "overwrite"})
    assert (workspace / "notes" / "new.txt").read_text(encoding="utf-8") == "three\n"
    no_parent = await h.call("write_file", {"path": "missing/dir/x.txt", "content": "x"})
    assert no_parent["result"]["isError"] is True


async def test_write_file_cannot_escape_or_follow_symlinks(harness, workspace: Path, tmp_path: Path) -> None:
    h: Harness = harness("maintainer")
    escape = await h.call("write_file", {"path": "../pwned.txt", "content": "x"})
    assert escape["result"]["isError"] is True and not (tmp_path / "pwned.txt").exists()
    _symlink(workspace / "hello.txt", workspace / "alias.txt")
    via_link = await h.call("write_file", {"path": "alias.txt", "content": "x", "mode": "overwrite"})
    assert via_link["result"]["isError"] is True and "symlink" in text_of(via_link)
    assert (workspace / "hello.txt").read_text(encoding="utf-8") == "hello world\n"
