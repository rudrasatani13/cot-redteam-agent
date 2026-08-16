"""Safe artifact path validation and root containment.

Guarantees provided by this module for user-supplied artifact relative
paths:

- the path is a non-empty string with no NUL or control characters;
- the path is relative under both POSIX and Windows semantics (Windows
  drive-letter and UNC forms are rejected via ``PureWindowsPath``);
- the path contains no ``..`` traversal segments;
- the final component is not a Windows reserved device name
  (``CON``/``PRN``/``AUX``/``NUL``/``COM1``-``9``/``LPT1``-``9``, matched
  case-insensitively with any extension), which would collide with a
  device or behave inconsistently across platforms;
- on Windows, no component contains ``:`` (an NTFS alternate data
  stream reference);
- every parent component of the destination is a real directory, never a
  symlink;
- the resolved parent of the destination stays strictly inside the pinned
  artifact root.

These guarantees are enforced before any filesystem write and re-validated
immediately before the atomic replace. A separate hostile local OS user
racing directory entries after validation is out of scope for this module;
see ``SECURITY.md``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

from cot_redteam.core.errors import StorageError

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TRAVERSAL_SEGMENT = ".."
# Windows reserved device names: valid to create on POSIX but meaningless
# (or a device) on Windows, with any extension.
_RESERVED_BASENAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


class UnsafePathError(StorageError):
    """Raised when an artifact path is unsafe or escapes the artifact root."""


def validate_relative_path(relative_path: str) -> str:
    """Validate and normalize a user-supplied artifact relative path.

    Returns a canonical forward-slash path with ``.`` and empty segments
    removed. Raises ``UnsafePathError`` on any violation.
    """
    if not isinstance(relative_path, str) or not relative_path:
        raise UnsafePathError("artifact path must be a non-empty string")
    if "\x00" in relative_path or _CONTROL_RE.search(relative_path):
        raise UnsafePathError("artifact path contains control characters")
    posix = PurePosixPath(relative_path)
    windows = PureWindowsPath(relative_path)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or windows.root:
        raise UnsafePathError(f"artifact path must be relative, got {relative_path!r}")
    segments = [
        part for part in relative_path.replace("\\", "/").split("/") if part not in ("", ".")
    ]
    if not segments:
        raise UnsafePathError("artifact path must name a file, not a directory")
    if _TRAVERSAL_SEGMENT in segments:
        raise UnsafePathError(f"artifact path must not contain '..' segments: {relative_path!r}")
    if sys.platform == "win32" and any(":" in part for part in segments):
        raise UnsafePathError(
            f"artifact path must not contain ':' components "
            f"(NTFS alternate data stream): {relative_path!r}"
        )
    if segments[-1].split(".")[0].upper() in _RESERVED_BASENAMES:
        raise UnsafePathError(
            f"artifact path must not use a reserved device name: {relative_path!r}"
        )
    return "/".join(segments)


def is_relative_to_resolved(child: Path, root: Path) -> bool:
    """True when ``child`` resolves to a path inside resolved ``root``."""
    resolved_root = root.resolve()
    resolved_child = child.resolve()
    try:
        resolved_child.relative_to(resolved_root)
        return True
    except ValueError:
        return False


def ensure_safe_parent(root: Path, relative_path: str) -> Path:
    """Create parent directories and return the validated destination.

    ``root`` is pinned via ``resolve()``. Existing or newly created parent
    components are checked for symlinks; the resolved parent is verified to
    stay inside the pinned root. Raises ``UnsafePathError`` otherwise.
    """
    normalized = validate_relative_path(relative_path)
    pinned = root.resolve()
    segments = normalized.split("/")
    current = pinned
    for segment in segments[:-1]:
        if current.is_symlink():
            raise UnsafePathError(f"artifact path traverses symlink: {normalized!r}")
        current = current / segment
        if current.is_symlink():
            raise UnsafePathError(f"artifact path traverses symlink: {normalized!r}")
        if not current.exists():
            try:
                current.mkdir()
            except FileExistsError:
                # Created concurrently between the exists() check and
                # mkdir(); tolerated only when it is a real directory,
                # verified below.
                pass
        if not current.is_dir():
            raise UnsafePathError(f"artifact path component is not a directory: {normalized!r}")
    destination = current / segments[-1]
    if destination.is_symlink():
        raise UnsafePathError(f"artifact destination must not be a symlink: {normalized!r}")
    if not is_relative_to_resolved(current, pinned):
        raise UnsafePathError(f"artifact path escapes artifact root: {normalized!r}")
    return destination
