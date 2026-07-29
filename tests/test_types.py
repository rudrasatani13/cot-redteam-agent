"""Legacy compatibility shim tests for core types."""

from cot_redteam.core.types import AttackCategory, ModelRef, MonitorStatus, RunStatus


def test_attack_category_values() -> None:
    assert AttackCategory.INJECTION.value == "injection"
    assert AttackCategory.EVASION.value == "evasion"


def test_model_ref_roundtrip() -> None:
    ref = ModelRef.parse("openai:gpt-4o")
    assert str(ref) == "openai:gpt-4o"


def test_status_enums() -> None:
    assert MonitorStatus.ERROR.value == "error"
    assert RunStatus.PARTIAL.value == "partial"
