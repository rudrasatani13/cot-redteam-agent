"""Educational system-canary payload bank for adaptive red-team loops.

Payloads are synthetic security-research templates used to measure whether a
model keeps a trusted system boundary. They are not for unauthorized probing
of third-party systems.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.types import AttackPrompt, DatasetSample, JsonValue

PACKAGE_BANK_MARKER = "pkg:system_canary_bank.jsonl"
DEFAULT_BANK_RESOURCE = "system_canary_bank.jsonl"


@dataclass(frozen=True)
class PayloadTemplate:
    """One educational attack framing from the bank."""

    id: str
    family: str
    template: str
    description: str = ""
    source: str = "builtin"

    def render(self, question: str) -> str:
        if "{question}" not in self.template:
            raise ValueError(f"payload {self.id!r} must contain {{question}}")
        return self.template.replace("{question}", question)


def _parse_row(row: Mapping[str, object], *, index: int) -> PayloadTemplate:
    payload_id = str(row.get("id") or f"payload_{index}").strip()
    template = row.get("template")
    if not isinstance(template, str) or not template.strip():
        raise ValueError(f"payload row {index}: template must be a non-empty string")
    if "{question}" not in template:
        raise ValueError(f"payload row {index}: template must contain {{question}}")
    family = str(row.get("family") or "general").strip() or "general"
    description = str(row.get("description") or "").strip()
    source = str(row.get("source") or "external").strip() or "external"
    return PayloadTemplate(
        id=payload_id,
        family=family,
        template=template,
        description=description,
        source=source,
    )


def load_payload_bank(path: str | Path | None = None) -> tuple[PayloadTemplate, ...]:
    """Load payload templates from a JSONL file or the packaged default bank."""
    if path is None or str(path).strip() in {
        "",
        PACKAGE_BANK_MARKER,
        "pkg:system_canary_bank",
        "package:system_canary_bank",
        "builtin",
    }:
        try:
            root = resources.files("cot_redteam.attacks.injection")
            resource = root.joinpath(DEFAULT_BANK_RESOURCE)
            text = resource.read_text(encoding="utf-8")
        except (FileNotFoundError, ModuleNotFoundError, TypeError, OSError) as exc:
            raise ConfigurationError(
                f"packaged payload bank not found ({DEFAULT_BANK_RESOURCE}): {exc}"
            ) from exc
        return _parse_jsonl_text(text, source_label=PACKAGE_BANK_MARKER)

    bank_path = Path(path)
    try:
        text = bank_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"unable to read payload bank {bank_path}: {exc}") from exc
    return _parse_jsonl_text(text, source_label=str(bank_path))


def _parse_jsonl_text(text: str, *, source_label: str) -> tuple[PayloadTemplate, ...]:
    payloads: list[PayloadTemplate] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(
                f"{source_label}:{line_no}: invalid JSON: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise ConfigurationError(f"{source_label}:{line_no}: expected a JSON object")
        try:
            payloads.append(_parse_row(row, index=line_no))
        except ValueError as exc:
            raise ConfigurationError(f"{source_label}:{line_no}: {exc}") from exc
    if not payloads:
        raise ConfigurationError(f"{source_label}: payload bank is empty")
    return tuple(payloads)


def filter_payloads(
    payloads: Sequence[PayloadTemplate],
    *,
    families: Sequence[str] | None = None,
    payload_ids: Sequence[str] | None = None,
    max_payloads: int | None = None,
) -> tuple[PayloadTemplate, ...]:
    selected = list(payloads)
    if families:
        allowed = {item.strip() for item in families if item.strip()}
        selected = [p for p in selected if p.family in allowed]
    if payload_ids:
        allowed_ids = {item.strip() for item in payload_ids if item.strip()}
        selected = [p for p in selected if p.id in allowed_ids]
    if max_payloads is not None:
        if max_payloads < 1:
            raise ValueError("max_payloads must be >= 1")
        selected = selected[:max_payloads]
    if not selected:
        raise ConfigurationError("payload bank filter produced zero payloads")
    return tuple(selected)


def build_prompts_from_bank(
    attack_id: str,
    sample: DatasetSample,
    payloads: Sequence[PayloadTemplate],
    *,
    system_prompt: str,
    extra_metadata: Mapping[str, JsonValue] | None = None,
) -> tuple[AttackPrompt, ...]:
    """Render every bank template into an AttackPrompt for adaptive looping."""
    prompts: list[AttackPrompt] = []
    base_meta = dict(extra_metadata or {})
    for index, payload in enumerate(payloads):
        text = payload.render(sample.question)
        meta: dict[str, JsonValue] = {
            **base_meta,
            "canary_protected": True,
            "payload_id": payload.id,
            "payload_family": payload.family,
            "payload_index": index,
            "payload_source": payload.source,
            "payload_description": payload.description,
            "adaptive": True,
        }
        prompts.append(
            AttackPrompt(
                attack_id=attack_id,
                text=text,
                system_prompt=system_prompt,
                sample_id=sample.id,
                metadata=meta,
            )
        )
    return tuple(prompts)


def iter_payload_ids(payloads: Sequence[PayloadTemplate]) -> Iterator[str]:
    for payload in payloads:
        yield payload.id
