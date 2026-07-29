"""Canonical serialization tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cot_redteam.core.serialization import canonical_json, sha256_bytes, sha256_file
from cot_redteam.core.types import ModelRef, MonitorStatus


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})


def test_hash_depends_on_bytes_not_path(tmp_path: Path) -> None:
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_bytes(b'{"a":1}')
    right.write_bytes(b'{"a":1}')
    assert sha256_file(left) == sha256_file(right)


def test_sha256_bytes() -> None:
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_canonical_json_handles_enums_and_datetimes() -> None:
    payload = {
        "status": MonitorStatus.ERROR,
        "when": datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        "ref": ModelRef.parse("openrouter:x/y"),
    }
    text = canonical_json(payload)
    assert '"status":"error"' in text
    assert "2026-01-02T03:04:05Z" in text
    assert '"provider":"openrouter"' in text
