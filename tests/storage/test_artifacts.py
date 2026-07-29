"""Artifact store tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from cot_redteam.storage.artifacts import ArtifactStore


def test_identical_bytes_same_hash(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    a = store.write_bytes("a/x.bin", b"hello")
    b = store.write_bytes("b/y.bin", b"hello")
    assert a.record.sha256 == b.record.sha256
    assert a.record.relative_path == "a/x.bin"


def test_partial_temp_cleaned_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = ArtifactStore(tmp_path)

    def boom(src, dst):
        raise OSError("fail rename")

    monkeypatch.setattr("os.replace", boom)
    with pytest.raises(OSError):
        store.write_bytes("out.bin", b"data")
    temps = list(tmp_path.glob("**/.tmp-*"))
    assert temps == []
