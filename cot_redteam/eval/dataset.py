"""Validated JSONL loading and deterministic dataset digests."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cot_redteam.core.errors import DatasetError
from cot_redteam.core.serialization import canonical_json, sha256_text
from cot_redteam.core.types import DatasetSample
from cot_redteam.resources import (
    is_package_dataset,
    package_dataset_file,
    sample_dataset_file,
)


@dataclass(frozen=True)
class Dataset:
    samples: tuple[DatasetSample, ...]
    digest: str
    path: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "samples", tuple(self.samples))

    @classmethod
    def load_jsonl(cls, path: str | Path) -> Dataset:
        if isinstance(path, str) and path.strip().startswith("pkg:"):
            name = path.strip()[4:].strip() or "sample.jsonl"
            if not name.endswith(".jsonl"):
                name += ".jsonl"
            with package_dataset_file(name) as pkg_path:
                return cls._load_from_path(pkg_path, display_path=path)
        if isinstance(path, str) and is_package_dataset(path):
            with sample_dataset_file() as pkg_path:
                return cls._load_from_path(pkg_path, display_path=path)
        return cls._load_from_path(Path(path), display_path=str(path))

    @classmethod
    def _load_from_path(cls, path: Path, *, display_path: str) -> Dataset:
        if not path.exists():
            raise DatasetError(f"dataset not found: {display_path}")
        samples: list[DatasetSample] = []
        digests: list[str] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                raw = line.strip()
                if not raw:
                    continue
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise DatasetError(f"line {line_no}: invalid JSON: {exc}") from exc
                if not isinstance(row, dict):
                    raise DatasetError(f"line {line_no}: expected object")
                if "id" not in row or "question" not in row:
                    raise DatasetError(f"line {line_no}: missing id or question")
                sample = DatasetSample(
                    id=str(row["id"]),
                    question=str(row["question"]),
                    answer=str(row["answer"]) if row.get("answer") is not None else None,
                    category=str(row["category"]) if row.get("category") is not None else None,
                    difficulty=(
                        str(row["difficulty"]) if row.get("difficulty") is not None else None
                    ),
                    metadata=row.get("metadata") or {},
                )
                samples.append(sample)
                digests.append(
                    canonical_json(
                        {
                            "id": sample.id,
                            "question": sample.question,
                            "answer": sample.answer,
                            "category": sample.category,
                            "difficulty": sample.difficulty,
                            "metadata": dict(sample.metadata),
                        }
                    )
                )
        if not samples:
            raise DatasetError(f"dataset is empty: {display_path}")
        digest = sha256_text("\n".join(digests))
        return cls(samples=tuple(samples), digest=digest, path=display_path)

    def select(
        self,
        *,
        sample_ids: Sequence[str] | None = None,
        sample_count: int | None = None,
        seed: int = 42,
    ) -> tuple[DatasetSample, ...]:
        by_id = {s.id: s for s in self.samples}
        if sample_ids is not None:
            missing = [sid for sid in sample_ids if sid not in by_id]
            if missing:
                raise DatasetError(f"unknown sample ids: {missing}")
            ordered = sorted(sample_ids)
            return tuple(by_id[sid] for sid in ordered)
        import random

        ids = sorted(by_id)
        if sample_count is not None:
            if sample_count > len(ids):
                raise DatasetError(f"sample_count {sample_count} exceeds dataset size {len(ids)}")
            rng = random.Random(seed)
            chosen = sorted(rng.sample(ids, sample_count))
            return tuple(by_id[sid] for sid in chosen)
        return tuple(by_id[sid] for sid in ids)
