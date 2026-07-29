"""Plugin registry and bootstrap."""

from cot_redteam.plugins.bootstrap import bootstrap_plugins, reset_plugins_for_tests
from cot_redteam.plugins.registry import PluginContext, PluginMetadata, Registry

__all__ = [
    "PluginContext",
    "PluginMetadata",
    "Registry",
    "bootstrap_plugins",
    "reset_plugins_for_tests",
]
