"""Artifact root containment and traversal rejection tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cot_redteam.core.errors import StorageError
from cot_redteam.core.serialization import sha256_bytes
from cot_redteam.storage.artifacts import ArtifactStore
from cot_redteam.storage.paths import UnsafePathError, validate_relative_path


@pytest.mark.parametrize(
    "unsafe",
    [
        "../escape.json",
        "a/../../escape.json",
        "a/../b/../escape.json",
        "/etc/escape.json",
        "//server/share/escape.json",
        "C:\\escape.json",
        "C:/escape.json",
        "\\\\server\\share\\escape.json",
        "a\\..\\escape.json",
        "a\x00b.json",
        "a\x1fb.json",
        "",
        ".",
        "./",
    ],
)
def test_unsafe_relative_paths_rejected(tmp_path: Path, unsafe: str) -> None:
    store = ArtifactStore(tmp_path)
    with pytest.raises(StorageError):
        store.write_bytes(unsafe, b"x")


def test_dotdot_write_rejected(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    with pytest.raises(UnsafePathError):
        store.write_bytes("../escape.json", b"x")
    assert not (tmp_path.parent / "escape.json").exists()


def test_nested_dotdot_write_rejected(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    with pytest.raises(UnsafePathError):
        store.write_bytes("a/../../escape.json", b"x")
    assert not (tmp_path / "a" / "escape.json").exists()


def test_absolute_posix_write_rejected(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    with pytest.raises(UnsafePathError):
        store.write_bytes("/etc/escape.json", b"x")


def test_windows_drive_write_rejected(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    with pytest.raises(UnsafePathError):
        store.write_bytes("C:\\escape.json", b"x")
    with pytest.raises(UnsafePathError):
        store.write_bytes("C:/escape.json", b"x")


def test_windows_unc_write_rejected(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    with pytest.raises(UnsafePathError):
        store.write_bytes("\\\\server\\share\\escape.json", b"x")


@pytest.mark.skipif(os.name == "nt", reason="symlink creation requires privileges on Windows")
def test_symlinked_parent_escaping_root_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    store = ArtifactStore(tmp_path)
    with pytest.raises(UnsafePathError):
        store.write_bytes("link/escape.json", b"x")
    assert not (outside / "escape.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="symlink creation requires privileges on Windows")
def test_symlink_destination_rejected(tmp_path: Path) -> None:
    target = tmp_path / "real.bin"
    target.write_bytes(b"real")
    (tmp_path / "victim.bin").symlink_to(target)
    store = ArtifactStore(tmp_path)
    with pytest.raises(UnsafePathError):
        store.write_bytes("victim.bin", b"x")
    # The symlink target must remain untouched.
    assert target.read_bytes() == b"real"


@pytest.mark.skipif(os.name == "nt", reason="symlink creation requires privileges on Windows")
def test_symlink_in_existing_tree_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "link").symlink_to(outside, target_is_directory=True)
    store = ArtifactStore(tmp_path)
    with pytest.raises(UnsafePathError):
        store.write_bytes("a/link/escape.json", b"x")
    assert not (outside / "escape.json").exists()


def test_normal_nested_write_succeeds(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    result = store.write_bytes("a/b/c.bin", b"hello")
    assert result.absolute_path == tmp_path / "a" / "b" / "c.bin"
    assert result.absolute_path.read_bytes() == b"hello"
    assert result.record.relative_path == "a/b/c.bin"


def test_backslash_separators_normalized(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    result = store.write_bytes("a\\b\\c.bin", b"hello")
    assert result.absolute_path == tmp_path / "a" / "b" / "c.bin"
    assert result.record.relative_path == "a/b/c.bin"


def test_checksum_matches_written_bytes(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    payload = b"checksum me reliably"
    result = store.write_bytes("data.bin", payload)
    assert result.record.sha256 == sha256_bytes(payload)
    assert result.record.byte_length == len(payload)


def test_dot_and_duplicate_segments_normalized(tmp_path: Path) -> None:
    assert validate_relative_path("a/./b//c.bin") == "a/b/c.bin"


def test_failed_write_leaves_no_final_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path)

    def boom(src, dst):
        raise OSError("fail rename")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        store.write_bytes("out.bin", b"data")
    assert not (tmp_path / "out.bin").exists()
    temps = list(tmp_path.glob("**/.tmp-*"))
    assert temps == []
