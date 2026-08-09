"""Agent Markdown and JSONL reporting.

Markdown reports the structural trajectory (sequence/event/tool/action/
status), authorization requested vs observed, state digests, budget ledger
by role, oracle table, and a retention notice. JSONL emits one strict
record per run/event/oracle/finding with a stable ``record_type``.
"""

from __future__ import annotations

import json

from cot_redteam.agent.config import AgentRetentionSettings
from cot_redteam.agent.retention import AgentSanitizer, sanitize_error_text
from cot_redteam.agent.types import (
    ActionEvent,
    AgentRun,
    ApprovalDecision,
    FinalResponse,
    MemoryMutation,
    SideEffect,
    ToolCallRequested,
    ToolResultReceived,
)
from cot_redteam.core.serialization import canonical_json


def _event_label(event: object) -> str:
    if isinstance(event, ToolCallRequested):
        return f"tool {event.tool_name} ({event.call_id})"
    if isinstance(event, ToolResultReceived):
        return f"result {event.tool_name} ({event.call_id})"
    if isinstance(event, ActionEvent):
        auth = event.authorization_state.value if event.authorization_state else "unknown"
        return f"action {event.action_kind} -> {auth}"
    if isinstance(event, ApprovalDecision):
        return f"approval {event.approval_id} {event.decision.value}"
    if isinstance(event, MemoryMutation):
        return f"memory {event.memory_namespace}:{event.key}"
    if isinstance(event, SideEffect):
        return f"effect {event.effect_kind}:{event.resource}"
    if isinstance(event, FinalResponse):
        return "final response" + (" (retained)" if event.text_retained else " (omitted)")
    return getattr(event, "step_kind", "")


def render_agent_markdown(
    run: AgentRun,
    *,
    replay_path: str | None = None,
    replay_checksum: str | None = None,
    retention: AgentRetentionSettings | None = None,
) -> str:
    diagnostic_sanitizer = AgentSanitizer(retention or AgentRetentionSettings())
    oracle_results = diagnostic_sanitizer.sanitize_oracle_result_collection(run.oracle_results)
    findings = tuple(diagnostic_sanitizer.sanitize_finding(finding) for finding in run.findings)
    lines: list[str] = []
    lines.append(f"# Agent Security Run {run.run_id}")
    lines.append("")
    lines.append(
        f"- scenario: `{run.scenario_ref.id}` v{run.scenario_ref.version}\n"
        f"- target: `{run.target_ref.id}` v{run.target_ref.version}\n"
        f"- world: `{run.world_ref.id}` v{run.world_ref.version}\n"
        f"- attack: `{run.attack_ref.id}` v{run.attack_ref.version}\n"
        f"- status: `{run.status.value}`\n"
        f"- outcome: **{run.outcome.value if run.outcome else 'none'}**"
    )
    if run.error:
        lines.append(f"- error: `{sanitize_error_text(run.error)}`")
    lines.append("")
    lines.append("## World state digests")
    lines.append("")
    lines.append(
        f"- pre: `{run.pre_snapshot_digest or '-'}`\n"
        f"- post: `{run.post_snapshot_digest or '-'}`\n"
        f"- trajectory: `{run.trajectory.digest or '-'}`"
    )
    lines.append("")
    lines.append("## Oracle results")
    lines.append("")
    lines.append("| oracle | version | verdict | evidence events |")
    lines.append("|---|---|---|---|")
    for result in oracle_results:
        events = ", ".join(result.evidence_event_ids) or "-"
        lines.append(
            f"| {result.oracle_id} | {result.oracle_version} | {result.verdict.value} | {events} |"
        )
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if findings:
        for finding in findings:
            lines.append(
                f"- `{finding.severity}` {finding.category}: {finding.summary} "
                f"(evidence: {', '.join(finding.evidence_event_ids) or '-'})"
            )
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Trajectory")
    lines.append("")
    lines.append("| seq | event | detail | status |")
    lines.append("|---|---|---|---|")
    for event in run.trajectory.events:
        status = event.status.value if event.status else ""
        lines.append(
            f"| {event.sequence_no} | `{event.event_type}` | {_event_label(event)} | {status} |"
        )
    lines.append("")
    lines.append("## Budget ledger by role")
    lines.append("")
    budget = run.budget_snapshot
    roles = budget.get("roles") or {}
    lines.append(f"- total requests: {budget.get('requests')}")
    if roles:
        for role, record in sorted(roles.items()):
            lines.append(
                f"- `{role}`: requests={record.get('requests')} "
                f"in={record.get('input_tokens')} out={record.get('output_tokens')} "
                f"cost={record.get('estimated_cost')}"
            )
    lines.append("")
    if replay_path is not None:
        lines.append("## Replay artifact")
        lines.append("")
        lines.append(f"- path: `{replay_path}`")
        if replay_checksum:
            lines.append(f"- sha256: `{replay_checksum}`")
        lines.append("")
    lines.append("## Retention")
    lines.append("")
    retained = (run.metadata or {}).get("retained") or {}
    lines.append(
        "- raw tool arguments/results, memory values, and final-response text "
        "are omitted by default unless explicitly retained; structural "
        "evidence (events, digests, oracles) is always kept."
    )
    lines.append(f"- configured: `{canonical_json(retained)}`")
    lines.append("")
    return "\n".join(lines)


def render_agent_jsonl(
    run: AgentRun,
    *,
    retention: AgentRetentionSettings | None = None,
) -> str:
    """One strict JSON record per run/event/oracle/finding."""
    diagnostic_sanitizer = AgentSanitizer(retention or AgentRetentionSettings())
    event_sanitizer = AgentSanitizer(retention) if retention is not None else None
    oracle_results = diagnostic_sanitizer.sanitize_oracle_result_collection(run.oracle_results)
    findings = tuple(diagnostic_sanitizer.sanitize_finding(finding) for finding in run.findings)
    records: list[dict[str, object]] = []
    records.append(
        {
            "record_type": "agent_run",
            "schema_version": run.schema_version,
            "run_id": run.run_id,
            "session_id": run.session_id,
            "scenario": run.scenario_ref.model_dump(mode="python"),
            "target": run.target_ref.model_dump(mode="python"),
            "world": run.world_ref.model_dump(mode="python"),
            "status": run.status.value,
            "outcome": run.outcome.value if run.outcome else None,
            "pre_snapshot_digest": run.pre_snapshot_digest,
            "post_snapshot_digest": run.post_snapshot_digest,
            "trajectory_digest": run.trajectory.digest,
            "error": sanitize_error_text(run.error),
            "budget": run.budget_snapshot,
        }
    )
    for event in run.trajectory.events:
        envelope = event.model_dump(mode="python")
        if event_sanitizer is not None:
            envelope = event_sanitizer.sanitize_event(envelope)
        records.append(
            {
                "record_type": "agent_event",
                "schema_version": run.schema_version,
                "run_id": run.run_id,
                "event": envelope,
            }
        )
    for result in oracle_results:
        records.append(
            {
                "record_type": "agent_oracle",
                "schema_version": run.schema_version,
                "run_id": run.run_id,
                "oracle_id": result.oracle_id,
                "oracle_version": result.oracle_version,
                "verdict": result.verdict.value,
                "summary": result.summary,
                "evidence_event_ids": list(result.evidence_event_ids),
            }
        )
    for finding in findings:
        records.append(
            {
                "record_type": "agent_finding",
                "schema_version": run.schema_version,
                "run_id": run.run_id,
                "finding_id": finding.finding_id,
                "oracle_id": finding.oracle_id,
                "category": finding.category,
                "severity": finding.severity,
                "summary": finding.summary,
                "evidence_event_ids": list(finding.evidence_event_ids),
            }
        )
    return "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n"
