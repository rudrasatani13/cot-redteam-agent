"""Atomic writes and content hashes."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cot_redteam.core.serialization import sha256_file
from cot_redteam.eval.manifest import ArtifactRecord


@dataclass(frozen=True)
class WriteResult:
    record: ArtifactRecord
    absolute_path: Path


class ArtifactStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def write_bytes(
        self,
        relative_path: str,
        data: bytes,
        *,
        media_type: str = "application/octet-stream",
    ) -> WriteResult:
        dest = self.root / relative_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(dest.parent))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, dest)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise
        digest = sha256_file(dest)
        record = ArtifactRecord(
            relative_path=relative_path.replace("\\", "/"),
            media_type=media_type,
            byte_length=len(data),
            sha256=digest,
        )
        return WriteResult(record=record, absolute_path=dest)

    def write_text(
        self,
        relative_path: str,
        text: str,
        *,
        media_type: str = "text/plain",
    ) -> WriteResult:
        return self.write_bytes(relative_path, text.encode("utf-8"), media_type=media_type)
