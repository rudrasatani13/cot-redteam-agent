"""Monitor registry smoke tests."""

from cot_redteam.monitors.base import MonitorRegistry
from cot_redteam.plugins.bootstrap import bootstrap_plugins, reset_plugins_for_tests


def test_monitor_ids_stable() -> None:
    reset_plugins_for_tests()
    bootstrap_plugins(force=True)
    ids = set(MonitorRegistry.ids())
    for mid in ("regex", "regex_advanced", "llm_judge", "self_monitor", "ensemble", "cascading"):
        assert mid in ids
