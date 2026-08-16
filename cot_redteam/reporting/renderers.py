"""Markdown, CSV, and LaTeX renderers."""

from __future__ import annotations

import csv
import io
import json
import re

from cot_redteam.reporting.model import ReportModel
from cot_redteam.reporting.owasp import owasp_mapping_version, owasp_tags_for

_LATEX_MAP = {
    "\\": r"\textbackslash{}",
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}


def latex_escape(value: str) -> str:
    return "".join(_LATEX_MAP.get(ch, ch) for ch in value)


def csv_neutralize(value: str) -> str:
    """Prefix spreadsheet formula triggers (= + - @ TAB CR) with an apostrophe.

    Shared by every CSV writer in the reporting package so hostile strings
    cannot execute as formulas when a report is opened in a spreadsheet.
    Bare carriage returns (not part of a ``\r\n`` pair) are flattened to a
    space: they are invalid inside unquoted CSV cells and trip the strict
    reader on Python 3.10 (whose writer does not quote lone ``\r`` fields).
    """
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        value = "'" + value
    return re.sub(r"\r(?!\n)", " ", value)


# Markdown sigils are backslash-escaped and HTML-significant characters are
# entity-escaped; newlines are flattened so hostile text cannot start a new
# block (heading, quote, list) on its own line.
_MD_ESCAPE_MAP = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "*": "\\*",
    "_": "\\_",
    "`": "\\`",
    "[": "\\[",
    "]": "\\]",
    "\\": "\\\\",
    "~": "\\~",
    "\n": " ",
    "\r": " ",
}

_BACKTICK_RUN = re.compile(r"`+")


def md_escape(value: str) -> str:
    """Escape model-derived text for safe inline use in Markdown.

    The threat model treats model and judge output as hostile: emphasis,
    link, and code sigils are escaped so payloads cannot forge report
    structure, and ``< > &`` are entity-escaped to neutralize raw HTML in
    HTML-rendering pipelines.
    """
    return "".join(_MD_ESCAPE_MAP.get(ch, ch) for ch in value)


def md_inline_code(value: str) -> str:
    """Render hostile text as an inline code span it cannot break out of.

    The delimiter run is one longer than any backtick run inside the text
    (the CommonMark rule), padded with spaces when needed, so backticks in
    model output can neither close the span early nor open a stray one.
    """
    text = value.replace("\r", " ").replace("\n", " ")
    longest = max((len(run) for run in _BACKTICK_RUN.findall(text)), default=0)
    fence = "`" * (longest + 1)
    if longest or text[:1] == " " or text[-1:] == " ":
        return f"{fence} {text} {fence}"
    return f"{fence}{text}{fence}"


def _markdown_code(value: str | None) -> list[str]:
    if value is None:
        return ["    (not retained or unavailable)"]
    lines = value.splitlines() or [""]
    return [f"    {line}" for line in lines]


def render_markdown(report: ReportModel) -> str:
    lines = [
        f"# CoT Red Team Report: {report.run_id}",
        "",
        f"- **Status:** {report.status}",
        f"- **Planned / Succeeded / Failed / Cancelled:** "
        f"{report.planned} / {report.succeeded} / {report.failed} / {report.cancelled}",
        f"- **Monitor excluded:** {report.monitor_excluded}",
        f"- **Attack success rate:** {report.attack_success_rate}",
        f"- **Evasion rate:** {report.evasion_rate} "
        f"(eligible={report.metrics.evasion.eligible}, excluded={report.metrics.evasion.excluded})",
        f"- **Provider failure rate:** {report.provider_failure_rate}",
        f"- **Monitor failure rate:** {report.monitor_failure_rate}",
        f"- **Models:** {', '.join(report.model_ids) or 'N/A'}",
        f"- **Attacks:** {', '.join(report.attack_ids) or 'N/A'}",
        f"- **Monitors:** {', '.join(report.monitor_ids) or 'N/A'}",
        f"- **Config digest:** {report.config_digest or 'N/A'}",
        f"- **Dataset digest:** {report.dataset_digest or 'N/A'}",
        "",
        "## Limitations",
        "",
    ]
    if report.limitations:
        lines.extend(f"- {item}" for item in report.limitations)
    else:
        lines.append("- None recorded")
    lines.extend(["", "## Evaluation Evidence", ""])
    for index, item in enumerate(report.items, start=1):
        lines.extend(
            [
                f"### Item {index}: {item.sample_id}",
                "",
                f"- **Status:** {item.status.value}",
                f"- **Model:** {item.model}",
                f"- **Attack:** {item.attack_id}",
            ]
        )
        owasp = owasp_tags_for(item.attack_id)
        if owasp:
            lines.append(f"- **{owasp_mapping_version()}:** {'; '.join(owasp)}")
        if item.error:
            lines.extend(["- **Error:**", "", *_markdown_code(item.error), ""])
        if item.prompt is not None:
            lines.extend(
                [
                    "",
                    "#### System Prompt",
                    "",
                    *_markdown_code(item.prompt.system_prompt),
                    "",
                    "#### Attack Prompt",
                    "",
                    *_markdown_code(item.prompt.text),
                ]
            )
            trace = item.prompt.metadata.get("attempt_history")
            if trace:
                lines.extend(["", "#### Adaptive Attempt Trace", ""])
                for row in trace:
                    attempt = row.get("attempt", "?")
                    payload = row.get("payload_id", "?")
                    verdict = "SUCCESS" if row.get("success") else "FAIL"
                    defense = row.get("defense_class", "?")
                    preview = str(row.get("response_preview") or "").strip()
                    lines.append(f"- **{attempt}. {payload}** — {verdict} (defense={defense})")
                    if preview:
                        lines.extend(["", *_markdown_code(preview)])
                    lines.append("")
        if item.response is not None:
            lines.extend(
                [
                    "",
                    "#### Response",
                    "",
                    *_markdown_code(item.response.text),
                    "",
                    f"- **Reasoning source:** {item.response.reasoning_source.value}",
                    f"- **Tokens (input/output/total):** {item.response.usage.input_tokens} / "
                    f"{item.response.usage.output_tokens} / {item.response.usage.total_tokens}",
                    "",
                    "#### Visible Provider Reasoning",
                    "",
                    *_markdown_code(item.response.reasoning),
                ]
            )
        if item.assessment is not None:
            evidence = item.assessment.evidence or ("None",)
            lines.extend(
                [
                    "",
                    "#### Attack Assessment",
                    "",
                    f"- **Success:** {str(item.assessment.success).lower()}",
                    f"- **Score:** {item.assessment.score:.3f}",
                    f"- **Explanation:** {md_escape(item.assessment.explanation or 'None')}",
                    "- **Evidence:**",
                    *(f"  - {md_escape(entry)}" for entry in evidence),
                ]
            )
        lines.extend(["", "#### Monitor Outcomes", ""])
        if not item.monitors:
            lines.append("- None")
        for outcome in item.monitors:
            confidence = "N/A" if outcome.confidence is None else f"{outcome.confidence:.3f}"
            details = json.dumps(outcome.details, ensure_ascii=False, sort_keys=True)
            lines.extend(
                [
                    f"- **{outcome.monitor_id}:** {outcome.status.value} "
                    f"(confidence={confidence}) — {md_escape(outcome.explanation)}",
                    "  - Details:",
                    "",
                    *_markdown_code(details),
                ]
            )
        lines.append("")
    lines.append("")
    return "\n".join(lines)


def render_csv(report: ReportModel) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["section", "key", "value"])
    for key, value in report.rows:
        writer.writerow(["summary", key, csv_neutralize(value)])
    for model_id in report.model_ids:
        # Neutralize formula characters in the full cell and model-id segment.
        writer.writerow(["models", "model_id", csv_neutralize(model_id)])
        if ":" in model_id:
            _, bare = model_id.split(":", 1)
            writer.writerow(["models", "bare_model_id", csv_neutralize(bare)])
    for attack_id in report.attack_ids:
        writer.writerow(["attacks", "attack_id", csv_neutralize(attack_id)])
    for limitation in report.limitations:
        writer.writerow(["limitations", "item", csv_neutralize(limitation)])
    return buf.getvalue()


def render_latex(report: ReportModel) -> str:
    pairs = list(report.rows)
    for model_id in report.model_ids:
        pairs.append(("model_id", model_id))
    for attack_id in report.attack_ids:
        pairs.append(("attack_id", attack_id))
    rows = "\n".join(f"{latex_escape(k)} & {latex_escape(v)} \\\\" for k, v in pairs)
    return f"\\begin{{tabular}}{{ll}}\n\\hline\n{rows}\n\\hline\n\\end{{tabular}}\n"
