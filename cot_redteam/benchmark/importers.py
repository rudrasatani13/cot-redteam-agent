"""Offline, non-executable adapters for selected external JSONL formats."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from cot_redteam.benchmark.schema import ScenarioSpec
from cot_redteam.benchmark.suite import ScenarioSuite
from cot_redteam.core.errors import DatasetError
from cot_redteam.core.serialization import sha256_file, sha256_text

IMPORTER_VERSION = "1.0.0"
_MAX_FILE_BYTES = 100 * 1024 * 1024
_MAX_ROW_BYTES = 512 * 1024
_KNOWN_ROLES = {"system", "developer", "user", "assistant", "tool"}


@dataclass(frozen=True)
class ImportSummary:
    imported: int
    skipped: int
    rejected: int
    rejection_reasons: Mapping[str, int]
    ignored_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class ImportResult:
    suite: ScenarioSuite
    summary: ImportSummary
    manifest: Mapping[str, Any]


def _literal_template(value: str) -> str:
    return value.replace("{", "{{").replace("}", "}}")


def _stable_suffix(value: str) -> str:
    return sha256_text(value)[:16]


def _read_rows(path: Path) -> list[tuple[int, dict[str, Any]]]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DatasetError(f"unable to inspect import source {path}: {exc}") from exc
    if size > _MAX_FILE_BYTES:
        raise DatasetError(f"import source exceeds {_MAX_FILE_BYTES} byte limit")
    rows: list[tuple[int, dict[str, Any]]] = []
    try:
        handle = path.open("r", encoding="utf-8")
    except OSError as exc:
        raise DatasetError(f"unable to read import source {path}: {exc}") from exc
    with handle:
        for line_no, line in enumerate(handle, start=1):
            if len(line.encode("utf-8")) > _MAX_ROW_BYTES:
                raise DatasetError(f"line {line_no}: row exceeds {_MAX_ROW_BYTES} byte limit")
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetError(f"line {line_no}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise DatasetError(f"line {line_no}: expected an object")
            rows.append((line_no, value))
    return rows


def _source(
    *,
    project: str,
    url: str,
    revision: str,
    license_id: str,
) -> dict[str, str]:
    return {
        "citation": f"{project}, revision {revision}",
        "url": url,
        "license": license_id,
    }


def _base_scenario(
    *,
    scenario_id: str,
    title: str,
    task: str,
    expected_output: str | None,
    target: str,
    steps: list[dict[str, str]],
    channel: str,
    source: dict[str, str],
) -> ScenarioSpec:
    capabilities = ["system_role"]
    roles = {step["role"] for step in steps}
    if "tool" in roles:
        capabilities.append("tool_role")
    if len([step for step in steps if step["role"] in {"user", "tool"}]) > 1:
        capabilities.append("multi_turn")
    if "developer" in roles:
        capabilities.append("developer_role")
    scorers = [{"id": "scorer.rogue_string.exact"}]
    if expected_output:
        scorers.extend(
            [
                {"id": "scorer.utility.expected_output"},
                {"id": "scorer.utility.false_refusal"},
            ]
        )
    return ScenarioSpec.model_validate(
        {
            "version": 1,
            "id": scenario_id,
            "title": title,
            "family": "imported_prompt_injection",
            "channel": channel,
            "task": {"prompt": task, "expected_output": expected_output},
            "objective": {"type": "emit_rogue_string", "target": target},
            "steps": steps,
            "required_capabilities": capabilities,
            "policy_ids": ["policy.hierarchy"],
            "technique_ids": ["technique.direct_extraction"],
            "transformation_ids": ["transform.identity"],
            "scorers": scorers,
            "source": source,
            "tags": ["imported", "prompt_injection"],
        }
    )


def _import(
    path: str | Path,
    *,
    suite_id: str,
    upstream_project: str,
    upstream_url: str,
    upstream_revision: str,
    upstream_license: str,
    convert: Callable[[dict[str, Any], dict[str, str]], ScenarioSpec],
    ignored_fields: tuple[str, ...] = (),
) -> ImportResult:
    source_path = Path(path)
    scenarios: list[ScenarioSpec] = []
    reasons: dict[str, int] = {}
    for _line_no, row in _read_rows(source_path):
        try:
            scenario = convert(
                row,
                _source(
                    project=upstream_project,
                    url=upstream_url,
                    revision=upstream_revision,
                    license_id=upstream_license,
                ),
            )
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            reason = str(exc).splitlines()[0] or "unsupported row"
            reasons[reason] = reasons.get(reason, 0) + 1
            continue
        scenarios.append(scenario)
    if not scenarios:
        raise DatasetError("no supported rows were imported")
    suite = ScenarioSuite.from_scenarios(
        scenarios,
        suite_id=suite_id,
        path=str(source_path),
    )
    rejected = sum(reasons.values())
    summary = ImportSummary(
        imported=len(scenarios),
        skipped=0,
        rejected=rejected,
        rejection_reasons=reasons,
        ignored_fields=ignored_fields,
    )
    manifest = {
        "upstream_project": upstream_project,
        "upstream_url": upstream_url,
        "upstream_revision": upstream_revision,
        "upstream_digest": sha256_file(source_path),
        "upstream_license": upstream_license,
        "importer_version": IMPORTER_VERSION,
        "suite_id": suite.id,
        "suite_digest": suite.digest,
        "counts": {
            "imported": summary.imported,
            "skipped": summary.skipped,
            "rejected": summary.rejected,
        },
        "rejection_reasons": dict(reasons),
        "ignored_fields": list(ignored_fields),
    }
    return ImportResult(suite=suite, summary=summary, manifest=manifest)


def _cyberseceval_row(row: dict[str, Any], source: dict[str, str]) -> ScenarioSpec:
    task = row.get("test_case_prompt") or row.get("user_input") or row.get("prompt")
    injection = row.get("injection_prompt") or row.get("attack_prompt")
    target = (
        row.get("injection_successful_response")
        or row.get("target")
        or row.get("expected_attack_output")
    )
    if not isinstance(task, str) or not task.strip():
        raise ValueError("missing textual test case prompt")
    if not isinstance(injection, str) or not injection.strip():
        raise ValueError("missing textual injection prompt")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("missing deterministic injection-success target")
    raw_id = str(row.get("id") or _stable_suffix(json.dumps(row, sort_keys=True)))
    suffix = _stable_suffix(raw_id)
    return _base_scenario(
        scenario_id=f"import.cyberseceval.{suffix}",
        title=f"Imported CyberSecEval case {raw_id}"[:200],
        task=task.strip(),
        expected_output=(
            row["expected_output"].strip() if isinstance(row.get("expected_output"), str) else None
        ),
        target=target.strip(),
        steps=[
            {
                "role": "user",
                "content": _literal_template(injection.strip()),
                "trust": "untrusted",
                "source": "external_document",
            }
        ],
        channel="indirect_document",
        source=source,
    )


def import_cyberseceval_jsonl(
    path: str | Path,
    *,
    suite_id: str,
    upstream_revision: str,
    upstream_license: str,
) -> ImportResult:
    return _import(
        path,
        suite_id=suite_id,
        upstream_project="Meta CyberSecEval",
        upstream_url="https://github.com/meta-llama/PurpleLlama",
        upstream_revision=upstream_revision,
        upstream_license=upstream_license,
        convert=_cyberseceval_row,
    )


def _ih_row(row: dict[str, Any], source: dict[str, str]) -> ScenarioSpec:
    messages = row.get("messages")
    target = row.get("target") or row.get("ideal") or row.get("expected_attack_output")
    if not isinstance(messages, list) or not messages:
        raise ValueError("missing messages array")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("missing deterministic target")
    system_parts: list[str] = []
    steps: list[dict[str, str]] = []
    for message in messages:
        if not isinstance(message, dict):
            raise ValueError("message must be an object")
        role = message.get("role")
        content = message.get("content")
        if role not in _KNOWN_ROLES or not isinstance(content, str) or not content.strip():
            raise ValueError("message has unsupported role or content")
        if role == "system":
            system_parts.append(content.strip())
            continue
        steps.append(
            {
                "role": role,
                "content": _literal_template(content.strip()),
                "trust": "untrusted",
                "source": "ih_challenge_message",
            }
        )
    if not steps:
        raise ValueError("row has no actionable non-system messages")
    task = "\n".join(system_parts) or "Follow the legitimate task in the conversation."
    raw_id = str(row.get("id") or _stable_suffix(json.dumps(row, sort_keys=True)))
    return _base_scenario(
        scenario_id=f"import.ih.{_stable_suffix(raw_id)}",
        title=f"Imported IH-Challenge case {raw_id}"[:200],
        task=task,
        expected_output=(
            row["expected_output"].strip() if isinstance(row.get("expected_output"), str) else None
        ),
        target=target.strip(),
        steps=steps,
        channel="scripted_conversation",
        source=source,
    )


def import_ih_challenge_jsonl(
    path: str | Path,
    *,
    suite_id: str,
    upstream_revision: str,
    upstream_license: str,
) -> ImportResult:
    return _import(
        path,
        suite_id=suite_id,
        upstream_project="OpenAI IH-Challenge",
        upstream_url="https://github.com/openai/ih-challenge",
        upstream_revision=upstream_revision,
        upstream_license=upstream_license,
        convert=_ih_row,
        ignored_fields=("grader_code_python",),
    )
