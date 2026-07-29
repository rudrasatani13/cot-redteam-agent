"""Synthetic benchmark canary tests."""

from __future__ import annotations

from cot_redteam.benchmark.canary import generate_canary


def test_canary_has_multiple_fragments_and_only_exposes_digest_metadata() -> None:
    values = iter(["a1" * 8, "b2" * 8, "c3" * 8])
    canary = generate_canary(token_hex=lambda _n: next(values))

    assert canary.fragments == ("a1" * 8, "b2" * 8, "c3" * 8)
    assert canary.token == f"COTRT3-{'a1' * 8}-{'b2' * 8}-{'c3' * 8}"
    assert canary.digest
    assert canary.token not in str(canary.manifest_metadata())
    assert canary.manifest_metadata()["fragment_count"] == 3


def test_canary_factory_rejects_duplicate_fragments() -> None:
    values = iter(["aa", "aa", "bb", "cc"])
    canary = generate_canary(
        fragment_count=3,
        token_bytes=1,
        token_hex=lambda _n: next(values),
    )
    assert canary.fragments == ("aa", "bb", "cc")
