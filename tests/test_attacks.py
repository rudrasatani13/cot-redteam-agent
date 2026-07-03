"""Test attack registry and auto-discovery."""
import pytest
from cot_redteam.attacks.base import AttackRegistry, auto_discover_attacks, BaseAttack
from cot_redteam.core.types import AttackCategory


@pytest.fixture(autouse=True)
def discover():
    auto_discover_attacks()


class TestRegistry:
    def test_attacks_registered(self):
        all_attacks = AttackRegistry.get_all()
        assert len(all_attacks) >= 20, f"Only {len(all_attacks)} attacks registered"

    def test_injection_attacks(self):
        attacks = AttackRegistry.get_by_category(AttackCategory.INJECTION)
        assert len(attacks) >= 3
        names = [a.name for a in attacks]
        assert "cot_injection" in names

    def test_faithfulness_attacks(self):
        attacks = AttackRegistry.get_by_category(AttackCategory.FAITHFULNESS)
        assert len(attacks) >= 3

    def test_steganography_attacks(self):
        attacks = AttackRegistry.get_by_category(AttackCategory.STEGANOGRAPHY)
        assert len(attacks) >= 3

    def test_manipulation_attacks(self):
        attacks = AttackRegistry.get_by_category(AttackCategory.MANIPULATION)
        assert len(attacks) >= 4

    def test_sandbagging_attacks(self):
        attacks = AttackRegistry.get_by_category(AttackCategory.SANDBAGGING)
        assert len(attacks) >= 3

    def test_evasion_attacks(self):
        attacks = AttackRegistry.get_by_category(AttackCategory.EVASION)
        assert len(attacks) >= 4

    def test_distillation_attacks(self):
        attacks = AttackRegistry.get_by_category(AttackCategory.DISTILLATION)
        assert len(attacks) >= 2

    def test_all_categories_represented(self):
        for cat in AttackCategory:
            attacks = AttackRegistry.get_by_category(cat)
            assert len(attacks) >= 1, f"No attacks for category: {cat.value}"

    def test_create_attack(self):
        attack = AttackRegistry.create("injection.cot_injection", {})
        assert attack is not None
        assert attack.name == "cot_injection"

    def test_list_names(self):
        names = AttackRegistry.list_names()
        assert "injection.cot_injection" in names
        assert len(names) >= 20