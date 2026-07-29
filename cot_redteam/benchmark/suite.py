"""Validated JSONL benchmark suite loading and deterministic digests."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from cot_redteam.benchmark.schema import ScenarioSpec
from cot_redteam.core.errors import DatasetError
from cot_redteam.core.serialization import canonical_json, sha256_text

_MAX_FILE_BYTES = 10 * 1024 * 1024
_MAX_ROW_BYTES = 256 * 1024
_SUITE_ID = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")


@dataclass(frozen=True)
class ScenarioSuite:
    id: str
    scenarios: tuple[ScenarioSpec, ...]
    digest: str
    path: str

    @classmethod
    def load_jsonl(cls, path: str | Path, *, suite_id: str) -> ScenarioSuite:
        suite_id = suite_id.strip()
        if not _SUITE_ID.fullmatch(suite_id):
            raise DatasetError("suite_id must be a lowercase stable identifier")
        source = Path(path)
        try:
            size = source.stat().st_size
        except OSError as exc:
            raise DatasetError(f"unable to inspect scenario suite {source}: {exc}") from exc
        if size > _MAX_FILE_BYTES:
            raise DatasetError(f"scenario suite exceeds {_MAX_FILE_BYTES} byte limit: {source}")

        scenarios: list[ScenarioSpec] = []
        seen_ids: set[str] = set()
        seen_content: set[str] = set()
        try:
            handle = source.open("r", encoding="utf-8")
        except OSError as exc:
            raise DatasetError(f"unable to read scenario suite {source}: {exc}") from exc

        with handle:
            for line_no, line in enumerate(handle, start=1):
                if len(line.encode("utf-8")) > _MAX_ROW_BYTES:
                    raise DatasetError(f"line {line_no}: row exceeds {_MAX_ROW_BYTES} byte limit")
                raw = line.strip()
                if not raw:
                    continue
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise DatasetError(f"line {line_no}: invalid JSON: {exc}") from exc
                if not isinstance(row, dict):
                    raise DatasetError(f"line {line_no}: expected an object")
                try:
                    scenario = ScenarioSpec.model_validate(row)
                except ValidationError as exc:
                    raise DatasetError(f"line {line_no}: invalid scenario: {exc}") from exc
                if scenario.id in seen_ids:
                    raise DatasetError(f"line {line_no}: duplicate scenario id {scenario.id!r}")
                if scenario.content_digest in seen_content:
                    raise DatasetError(
                        f"line {line_no}: duplicate scenario content for {scenario.id!r}"
                    )
                seen_ids.add(scenario.id)
                seen_content.add(scenario.content_digest)
                scenarios.append(scenario)

        if not scenarios:
            raise DatasetError(f"scenario suite is empty: {source}")
        digest = sha256_text(
            "\n".join(canonical_json(scenario.model_dump(mode="python")) for scenario in scenarios)
        )
        return cls(
            id=suite_id,
            scenarios=tuple(scenarios),
            digest=digest,
            path=str(source),
        )
