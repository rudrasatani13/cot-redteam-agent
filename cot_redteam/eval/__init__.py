"""Evaluation package (lazy re-exports).

The public surface is unchanged; imports are deferred so
``cot_redteam.core.invocation`` (which depends on ``eval.budgets``) can be
imported without triggering ``eval.engine`` first, which would otherwise
create a circular import.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cot_redteam.eval.dataset import Dataset
    from cot_redteam.eval.engine import EvaluationEngine
    from cot_redteam.eval.metrics import summarize_run
    from cot_redteam.eval.planner import RunPlan, RunPlanner

__all__ = [
    "Dataset",
    "EvaluationEngine",
    "RunPlan",
    "RunPlanner",
    "summarize_run",
]


def __getattr__(name: str) -> object:
    if name == "Dataset":
        from cot_redteam.eval.dataset import Dataset

        return Dataset
    if name == "EvaluationEngine":
        from cot_redteam.eval.engine import EvaluationEngine

        return EvaluationEngine
    if name == "summarize_run":
        from cot_redteam.eval.metrics import summarize_run

        return summarize_run
    if name in ("RunPlan", "RunPlanner"):
        from cot_redteam.eval.planner import RunPlan, RunPlanner

        return {"RunPlan": RunPlan, "RunPlanner": RunPlanner}[name]
    raise AttributeError(name)
