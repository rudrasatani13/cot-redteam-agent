"""SARIF 2.1.0 export for evaluation runs and compliance scans.

Converts an evaluation run into a SARIF log so findings can be ingested by
GitHub code scanning (upload-sarif), GitHub Advanced Security, or any other
SARIF reader. Semantics mirror the project's no-overclaiming rules:

- an item whose assessment succeeded (a real disclosure / compliance
  finding) becomes a result with level "error";
- an item with a triggered monitor (evasion) becomes a result with level
  "warning";
- an item that did not complete (provider/attack/monitor error or budget
  exhaustion) becomes a result with level "note" so partial coverage is
  visible and a run is never silently clean;
- clean items emit no result, and a fully clean run emits an empty result
  list with a successful invocation.

Every rule carries the OWASP GenAI LLM Top 10 tags of its attack family
and the mapping version, so scanner output stays aligned with the report
tags emitted by the Markdown/CSV/LaTeX renderers.
"""

from __future__ import annotations

import json
from typing import Any

from cot_redteam import __version__ as TOOL_VERSION
from cot_redteam.core.types import EvaluationItem, EvaluationRun, ItemStatus, MonitorStatus
from cot_redteam.reporting.owasp import owasp_mapping_version, owasp_tags_for

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "cot-redteam-agent"
INFORMATION_URI = "https://github.com/rudrasatani13/cot-redteam-agent"

_INCOMPLETE_STATUSES = frozenset(
    {
        ItemStatus.PROVIDER_ERROR,
        ItemStatus.ATTACK_ERROR,
        ItemStatus.MONITOR_ERROR,
        ItemStatus.BUDGET_EXCEEDED,
    }
)


def _rule_id(attack_id: str) -> str:
    return f"cot-redteam/{attack_id}"


def _result_for(item: EvaluationItem) -> dict[str, Any] | None:
    """Map one evaluation item to a SARIF result; clean items produce
    none."""
    attack = item.attack_id
    model = str(item.model)
    if item.assessment is not None and item.assessment.success:
        level = "error"
        message = (
            f"attack {attack!r} succeeded against {model}: compliant "
            "disclosure produced by the target."
        )
    elif any(o.status is MonitorStatus.TRIGGERED for o in item.monitors):
        level = "warning"
        message = f"monitor triggered for attack {attack!r} against {model}."
    elif item.status in _INCOMPLETE_STATUSES:
        level = "note"
        detail = item.error or item.status.value
        message = f"item did not complete for attack {attack!r} against {model}: {detail}"
    else:
        return None
    return {
        "ruleId": _rule_id(attack),
        "level": level,
        "message": {"text": message},
        "properties": {
            "attack_id": attack,
            "model": model,
            "status": item.status.value,
            "success": bool(item.assessment is not None and item.assessment.success),
        },
    }


def build_sarif_report(
    run: EvaluationRun,
    *,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log for an evaluation run."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in run.items:
        result = _result_for(item)
        if result is None:
            continue
        results.append(result)
        rule_id = result["ruleId"]
        if rule_id not in rules:
            owasp = tuple(owasp_tags_for(item.attack_id))
            if owasp:
                owasp_text = f"OWASP {owasp_mapping_version()} tags: " + "; ".join(owasp)
            else:
                owasp_text = f"no OWASP {owasp_mapping_version()} mapping"
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": item.attack_id},
                "fullDescription": {
                    "text": f"{item.attack_id} — red-team attack family. {owasp_text}.",
                },
                "properties": {
                    "attack_id": item.attack_id,
                    "owasp_version": owasp_mapping_version(),
                    "owasp_tags": list(owasp),
                },
            }
    invocation: dict[str, Any] = {
        "executionSuccessful": run.status.value not in ("failed", "partial"),
        "properties": {
            "run_id": run.run_id,
            "status": run.status.value,
            "seed": run.seed,
            "dataset_digest": run.dataset_digest,
            "planned": run.summary.planned,
            "succeeded": run.summary.succeeded,
            "failed": run.summary.failed,
        },
    }
    if run.completed_at is not None:
        invocation["endTimeUtc"] = run.completed_at.isoformat().replace("+00:00", "Z")
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": tool_version or TOOL_VERSION,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
                "invocations": [invocation],
            },
        ],
    }


def render_sarif(
    run: EvaluationRun,
    *,
    tool_version: str | None = None,
) -> str:
    """Render a SARIF log as pretty-printed, deterministic JSON."""
    return json.dumps(build_sarif_report(run, tool_version=tool_version), indent=2, sort_keys=True)
