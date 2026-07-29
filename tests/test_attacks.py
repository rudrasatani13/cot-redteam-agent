"""Attack registry smoke tests."""

from cot_redteam.attacks.base import AttackRegistry
from cot_redteam.plugins.bootstrap import bootstrap_plugins, reset_plugins_for_tests


def test_attack_ids_stable() -> None:
    reset_plugins_for_tests()
    bootstrap_plugins(force=True)
    ids = set(AttackRegistry.ids())
    assert "injection.cot_injection" in ids
    assert "evasion.nl_camouflage" in ids
    assert "generative.evolved" in ids
