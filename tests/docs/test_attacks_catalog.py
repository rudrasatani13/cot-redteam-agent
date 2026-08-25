"""Attack catalog coverage checks."""

from __future__ import annotations

import re
from pathlib import Path

from cot_redteam.attacks.base import AttackRegistry
from cot_redteam.plugins.bootstrap import bootstrap_plugins


def test_attack_catalog_lists_each_registered_attack_once() -> None:
    bootstrap_plugins()
    catalog = (Path(__file__).parents[2] / "docs" / "attacks.md").read_text()
    documented = re.findall(r"^\| `([a-z0-9_]+\.[a-z0-9_]+)` \|", catalog, re.MULTILINE)
    registered = [metadata.id for metadata in AttackRegistry.metadata()]

    assert sorted(documented) == sorted(registered)
    assert len(documented) == len(set(documented))
