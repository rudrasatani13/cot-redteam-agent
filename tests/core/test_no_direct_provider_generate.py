"""Static guard: production model calls must route through InvocationService.

The provider boundary owns transport-level retries; ``core/invocation.py`` is
the only place that may invoke ``Provider.generate`` directly. This AST-level
regression test fails when production code outside provider implementations
and the invocation boundary calls ``.generate(...)`` on a provider.

Explicit scope note: this is a core-maintenance guard, not a plugin
sandbox. A trusted third-party Python plugin can still bypass it by
executing arbitrary Python, which is the documented plugin contract.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2] / "cot_redteam"
ALLOWED_DIR_PREFIXES = ("providers",)
ALLOWED_FILES = {"core/invocation.py"}


def _python_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in str(path))


def _direct_generate_calls(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "generate":
                lines.append(node.lineno)
    return lines


def test_no_direct_provider_generate_outside_boundary() -> None:
    offenders: list[str] = []
    for path in _python_files(PACKAGE):
        rel = path.relative_to(PACKAGE).as_posix()
        if rel.startswith(ALLOWED_DIR_PREFIXES) or rel in ALLOWED_FILES:
            continue
        for lineno in _direct_generate_calls(path):
            offenders.append(f"{rel}:{lineno}: direct .generate() call")
    assert not offenders, (
        "Every built-in logical model call must route through "
        "cot_redteam.core.invocation (InvocationService.invoke or "
        "invoke_provider). Found direct calls:\n" + "\n".join(offenders)
    )


def test_invocation_boundary_owns_generate() -> None:
    """The boundary itself must contain at least one direct generate call."""
    boundary = PACKAGE / "core" / "invocation.py"
    assert _direct_generate_calls(boundary), "invocation boundary no longer calls generate?"
