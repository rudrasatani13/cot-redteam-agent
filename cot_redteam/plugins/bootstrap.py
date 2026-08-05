"""Built-in imports and Python entry-point discovery."""

from __future__ import annotations

import importlib
import importlib.metadata
from collections.abc import Iterable

from cot_redteam.core.errors import PluginError

_BOOTSTRAPPED = False

_BUILTIN_MODULES = (
    "cot_redteam.attacks.injection.attacks",
    "cot_redteam.attacks.injection.agent",
    "cot_redteam.attacks.injection.agent_llm",
    "cot_redteam.attacks.injection.crescendo",
    "cot_redteam.attacks.faithfulness.attacks",
    "cot_redteam.attacks.steganography.attacks",
    "cot_redteam.attacks.manipulation.attacks",
    "cot_redteam.attacks.sandbagging.attacks",
    "cot_redteam.attacks.evasion.attacks",
    "cot_redteam.attacks.distillation.attacks",
    "cot_redteam.attacks.generative.engine",
    "cot_redteam.monitors.regex_monitor",
    "cot_redteam.monitors.llm_judge",
    "cot_redteam.monitors.ensemble",
    "cot_redteam.monitors.evasion",
)


def _load_entry_points(group: str) -> None:
    try:
        eps = importlib.metadata.entry_points()
    except Exception as exc:  # pragma: no cover
        raise PluginError(f"failed to read entry points: {exc}") from exc

    selected: Iterable[importlib.metadata.EntryPoint]
    if hasattr(eps, "select"):
        selected = eps.select(group=group)
    else:  # pragma: no cover
        selected = eps.get(group, [])  # type: ignore[assignment]

    for ep in selected:
        try:
            ep.load()
        except Exception as exc:
            dist = getattr(ep, "dist", None)
            dist_name = dist.name if dist is not None else "unknown"
            raise PluginError(
                f"failed to load entry point {ep.name!r} from distribution {dist_name!r}: {exc}"
            ) from exc


def bootstrap_plugins(*, force: bool = False) -> None:
    """Import built-ins and third-party entry points once."""
    global _BOOTSTRAPPED
    from cot_redteam.attacks.base import AttackRegistry
    from cot_redteam.monitors.base import MonitorRegistry

    registries_empty = not AttackRegistry.ids() or not MonitorRegistry.ids()
    if _BOOTSTRAPPED and not force and not registries_empty:
        return

    # After registry.clear() in tests, modules stay cached; re-run registration.
    need_reload = force or registries_empty
    for module_name in _BUILTIN_MODULES:
        module = importlib.import_module(module_name)
        if need_reload:
            importlib.reload(module)

    _load_entry_points("cot_redteam.attacks")
    _load_entry_points("cot_redteam.monitors")
    _BOOTSTRAPPED = True


def reset_plugins_for_tests() -> None:
    """Test-only hook to clear registries and bootstrap cache."""
    global _BOOTSTRAPPED
    from cot_redteam.attacks.base import AttackRegistry
    from cot_redteam.monitors.base import MonitorRegistry

    AttackRegistry.clear()
    MonitorRegistry.clear()
    _BOOTSTRAPPED = False
