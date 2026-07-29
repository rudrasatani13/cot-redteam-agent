"""Conservative visible-reasoning extraction."""

from __future__ import annotations

from cot_redteam.core.types import ReasoningSource

DEFAULT_DELIMITER_PAIRS: tuple[tuple[str, str], ...] = (
    ("<think>", "</think>"),
    ("<reasoning>", "</reasoning>"),
)


def _pairs_from_delimiters(
    delimiters: list[str] | tuple[str, ...] | None,
) -> tuple[tuple[str, str], ...]:
    if not delimiters:
        return DEFAULT_DELIMITER_PAIRS
    pairs: list[tuple[str, str]] = []
    items = list(delimiters)
    i = 0
    while i < len(items):
        open_tag = items[i]
        close_tag = items[i + 1] if i + 1 < len(items) else None
        # Only accept explicit open/close pairs that look like tags.
        if (
            close_tag
            and open_tag.startswith("<")
            and close_tag.startswith("</")
            and open_tag.endswith(">")
            and close_tag.endswith(">")
        ):
            pairs.append((open_tag, close_tag))
            i += 2
        else:
            i += 1
    return tuple(pairs) if pairs else DEFAULT_DELIMITER_PAIRS


def extract_visible_reasoning(
    text: str,
    delimiters: list[str] | tuple[str, ...] | None = None,
    *,
    provider_reasoning: str | None = None,
) -> tuple[str | None, ReasoningSource]:
    """Extract visible reasoning from provider fields or explicit delimiter pairs.

    Ordinary answer text containing reasoning keywords is never labeled as
    reasoning.
    """
    if provider_reasoning is not None and provider_reasoning.strip():
        return provider_reasoning.strip(), ReasoningSource.PROVIDER

    if not text:
        return None, ReasoningSource.ABSENT

    for open_tag, close_tag in _pairs_from_delimiters(delimiters):
        start = text.find(open_tag)
        if start < 0:
            continue
        content_start = start + len(open_tag)
        end = text.find(close_tag, content_start)
        if end < 0:
            # Unclosed delimiter pair → do not invent reasoning.
            continue
        content = text[content_start:end].strip()
        if content:
            return content, ReasoningSource.DELIMITED

    return None, ReasoningSource.ABSENT
