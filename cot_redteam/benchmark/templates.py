"""Bounded template validation and rendering without executable expressions."""

from __future__ import annotations

import re
from collections.abc import Mapping, Set
from string import Formatter

_SIMPLE_VARIABLE = re.compile(r"^[a-z][a-z0-9_]*$")
ATTACK_TEMPLATE_VARIABLES = frozenset({"task", "rogue_string", "untrusted_content", "label"})
POLICY_TEMPLATE_VARIABLES = frozenset({"canary", "task", "untrusted_content_label"})


def template_variables(template: str) -> tuple[str, ...]:
    """Return validated simple variable names referenced by a template."""
    fields: list[str] = []
    try:
        parsed = Formatter().parse(template)
        for _, field_name, format_spec, conversion in parsed:
            if field_name is None:
                continue
            if not _SIMPLE_VARIABLE.fullmatch(field_name):
                raise ValueError(f"template field {field_name!r} must be a simple variable name")
            if format_spec or conversion:
                raise ValueError("template formatting and conversions are not allowed")
            fields.append(field_name)
    except ValueError as exc:
        if str(exc).startswith("template"):
            raise
        raise ValueError(f"invalid template: {exc}") from exc
    return tuple(dict.fromkeys(fields))


def validate_template(template: str, *, allowed_variables: Set[str]) -> None:
    if not template or not template.strip():
        raise ValueError("template must be non-empty")
    for field_name in template_variables(template):
        if field_name not in allowed_variables:
            raise ValueError(f"template variable {field_name!r} is not allowed")


def render_template(
    template: str,
    values: Mapping[str, str],
    *,
    allowed_variables: Set[str],
) -> str:
    """Render a validated template using only explicitly allowed string values."""
    validate_template(template, allowed_variables=allowed_variables)
    referenced = template_variables(template)
    missing = [name for name in referenced if name not in values]
    if missing:
        raise ValueError(f"missing template variables: {', '.join(missing)}")
    rendered = template.format_map({name: str(values[name]) for name in referenced})
    if not rendered.strip():
        raise ValueError("rendered template must be non-empty")
    return rendered
