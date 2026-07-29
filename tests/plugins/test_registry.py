"""Generic registry tests."""

from __future__ import annotations

import pytest

from cot_redteam.core.errors import PluginError
from cot_redteam.plugins.registry import PluginMetadata, Registry


def test_registry_rejects_duplicate_id() -> None:
    registry: Registry[object] = Registry("attack")
    metadata = PluginMetadata(id="injection.demo", version="1.0.0", description="demo")
    registry.register(metadata, lambda config, context: object())
    with pytest.raises(PluginError, match="duplicate attack plugin"):
        registry.register(metadata, lambda config, context: object())


def test_unknown_id_lists_available_plugins() -> None:
    registry: Registry[object] = Registry("monitor")
    metadata = PluginMetadata(id="regex", version="1.0.0", description="regex")
    registry.register(metadata, lambda config, context: object())
    with pytest.raises(PluginError, match="Available: regex"):
        registry.create("missing", {})


def test_metadata_sorted_by_id() -> None:
    registry: Registry[object] = Registry("attack")
    registry.register(
        PluginMetadata(id="b", version="1", description="b"),
        lambda c, x: object(),
    )
    registry.register(
        PluginMetadata(id="a", version="1", description="a"),
        lambda c, x: object(),
    )
    assert [m.id for m in registry.metadata()] == ["a", "b"]
