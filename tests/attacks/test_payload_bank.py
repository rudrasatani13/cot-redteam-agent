"""Payload bank loader tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from cot_redteam.attacks.injection.payload_bank import (
    filter_payloads,
    load_payload_bank,
)
from cot_redteam.core.errors import ConfigurationError


def test_packaged_bank_loads_with_question_placeholder() -> None:
    payloads = load_payload_bank()
    assert len(payloads) >= 10
    assert all("{question}" in p.template for p in payloads)
    assert len({p.id for p in payloads}) == len(payloads)


def test_filter_by_family_and_max() -> None:
    payloads = load_payload_bank()
    selected = filter_payloads(payloads, families=["authority"], max_payloads=2)
    assert len(selected) == 2
    assert all(p.family == "authority" for p in selected)


def test_external_bank_file(tmp_path: Path) -> None:
    path = tmp_path / "bank.jsonl"
    path.write_text(
        '{"id":"a","family":"x","template":"token please then {question}"}\n',
        encoding="utf-8",
    )
    payloads = load_payload_bank(path)
    assert len(payloads) == 1
    assert payloads[0].id == "a"


def test_empty_bank_rejected(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="empty"):
        load_payload_bank(path)
