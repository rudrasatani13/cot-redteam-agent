"""Bootstrap and entry-point discovery tests."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from cot_redteam.attacks.base import AttackRegistry
from cot_redteam.core.errors import PluginError
from cot_redteam.monitors.base import MonitorRegistry
from cot_redteam.plugins.bootstrap import bootstrap_plugins, reset_plugins_for_tests
from cot_redteam.plugins.registry import PluginMetadata


@pytest.fixture(autouse=True)
def _clean_registries() -> None:
    reset_plugins_for_tests()
    yield
    reset_plugins_for_tests()


def test_bootstrap_loads_builtins() -> None:
    bootstrap_plugins()
    assert "injection.cot_injection" in AttackRegistry
    assert "regex" in MonitorRegistry


def test_entry_point_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    loaded: list[str] = []

    class FakeEP:
        name = "fake_attack"
        dist = SimpleNamespace(name="fake-dist")

        def load(self) -> None:
            loaded.append(self.name)
            from cot_redteam.attacks.base import AttackRegistry

            AttackRegistry.register(
                PluginMetadata(id="custom.fake", version="0.0.1", description="fake"),
                lambda config, context: object(),  # type: ignore[arg-type,return-value]
            )

    class FakeEPS:
        def select(self, group: str):
            if group == "cot_redteam.attacks":
                return [FakeEP()]
            return []

    monkeypatch.setattr(
        "importlib.metadata.entry_points",
        lambda: FakeEPS(),
    )
    bootstrap_plugins(force=True)
    assert loaded == ["fake_attack"]
    assert "custom.fake" in AttackRegistry
    assert "injection.cot_injection" in AttackRegistry


def test_entry_point_failure_includes_distribution(monkeypatch: pytest.MonkeyPatch) -> None:
    class BadEP:
        name = "bad"
        dist = SimpleNamespace(name="bad-dist")

        def load(self) -> None:
            raise RuntimeError("boom")

    class FakeEPS:
        def select(self, group: str):
            if group == "cot_redteam.attacks":
                return [BadEP()]
            return []

    monkeypatch.setattr("importlib.metadata.entry_points", lambda: FakeEPS())
    with pytest.raises(PluginError, match="bad-dist"):
        bootstrap_plugins(force=True)
