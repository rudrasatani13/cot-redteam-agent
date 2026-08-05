"""Package resource resolution for wheel-safe install paths."""

from __future__ import annotations

import importlib.resources
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cot_redteam.core.errors import ConfigurationError

PACKAGE_DATASET_MARKER = "pkg:sample.jsonl"
EXAMPLE_CONFIG_RESOURCE = "config.example.yaml"
SAMPLE_DATASET_RESOURCE = "sample.jsonl"


def read_example_config_text() -> str:
    """Return the packaged example configuration as text."""
    try:
        root = importlib.resources.files("cot_redteam.data")
        return root.joinpath(EXAMPLE_CONFIG_RESOURCE).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, TypeError, OSError) as exc:
        raise ConfigurationError(
            f"packaged example config not found ({EXAMPLE_CONFIG_RESOURCE}): {exc}"
        ) from exc


@contextmanager
def sample_dataset_file() -> Iterator[Path]:
    """Yield a filesystem path to the packaged sample dataset (wheel-safe)."""
    with package_dataset_file(SAMPLE_DATASET_RESOURCE) as path:
        yield path


@contextmanager
def package_dataset_file(name: str) -> Iterator[Path]:
    """Yield a filesystem path to a packaged eval dataset (wheel-safe).

    ``name`` must be a bare filename inside ``cot_redteam/eval/datasets``;
    path separators are rejected so the pkg: marker cannot escape the
    package directory.
    """
    if "/" in name or "\\" in name or name.startswith(".."):
        raise ConfigurationError(f"invalid packaged dataset name: {name!r}")
    try:
        root = importlib.resources.files("cot_redteam.eval.datasets")
        resource = root.joinpath(name)
    except (ModuleNotFoundError, TypeError) as exc:
        raise ConfigurationError(f"packaged dataset unavailable: {exc}") from exc
    with importlib.resources.as_file(resource) as path:
        if not path.exists():
            raise ConfigurationError(f"packaged dataset missing: {path}")
        yield Path(path)


def is_package_dataset(path: str) -> bool:
    value = path.strip()
    return value in {
        PACKAGE_DATASET_MARKER,
        "package:sample",
        "pkg:sample",
        "sample",
    }


def resolve_path_against_config(path: str | Path, config_path: Path | None) -> Path:
    """Resolve a path; relative paths are relative to the config file directory.

    Package markers (`pkg:...`) are returned unchanged — they are resolved
    later against the installed package, not the filesystem.
    """
    p = Path(path)
    if isinstance(path, str) and (path.strip().startswith("pkg:") or is_package_dataset(path)):
        return p
    if p.is_absolute():
        return p
    if config_path is not None:
        return (config_path.parent / p).resolve()
    return p.resolve()
