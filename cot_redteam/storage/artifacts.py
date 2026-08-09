"""Atomic writes and content hashes."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cot_redteam.core.serialization import sha256_file
from cot_redteam.eval.manifest import ArtifactRecord
from cot_redteam.storage.paths import (
    UnsafePathError,
    ensure_safe_parent,
    is_relative_to_resolved,
    validate_relative_path,
)


@dataclass(frozen=True)
class WriteResult:
    record: ArtifactRecord
    absolute_path: Path


class ArtifactStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _revalidate_destination(self, destination: Path, normalized: str) -> None:
        """Re-check containment immediately before the atomic replace."""
        if not is_relative_to_resolved(destination.parent, self.root):
            raise UnsafePathError(f"artifact path escapes artifact root: {normalized!r}")
        if destination.is_symlink():
            raise UnsafePathError(f"artifact destination must not be a symlink: {normalized!r}")
        if destination.exists() and not destination.is_file():
            raise UnsafePathError(f"artifact destination is not a regular file: {normalized!r}")

    def write_bytes(
        self,
        relative_path: str,
        data: bytes,
        *,
        media_type: str = "application/octet-stream",
    ) -> WriteResult:
        normalized = validate_relative_path(relative_path)
        dest = ensure_safe_parent(self.root, normalized)
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(dest.parent))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            # Revalidate immediately before replace: another code path could
            # have swapped a parent directory for a symlink since the initial
            # check (TOCTOU against a hostile local user remains documented
            # as out of scope in SECURITY.md).
            self._revalidate_destination(dest, normalized)
            os.replace(tmp_path, dest)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise
        digest = sha256_file(dest)
        record = ArtifactRecord(
            relative_path=normalized,
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
