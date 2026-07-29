"""Markdown, CSV, and LaTeX renderers."""

from __future__ import annotations

import csv
import io

from cot_redteam.reporting.model import ReportModel

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


def _csv_neutralize(value: str) -> str:
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


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
    lines.append("")
    return "\n".join(lines)


def render_csv(report: ReportModel) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["section", "key", "value"])
    for key, value in report.rows:
        writer.writerow(["summary", key, _csv_neutralize(value)])
    for model_id in report.model_ids:
        # Neutralize formula characters in the full cell and model-id segment.
        writer.writerow(["models", "model_id", _csv_neutralize(model_id)])
        if ":" in model_id:
            _, bare = model_id.split(":", 1)
            writer.writerow(["models", "bare_model_id", _csv_neutralize(bare)])
    for attack_id in report.attack_ids:
        writer.writerow(["attacks", "attack_id", _csv_neutralize(attack_id)])
    for limitation in report.limitations:
        writer.writerow(["limitations", "item", _csv_neutralize(limitation)])
    return buf.getvalue()


def render_latex(report: ReportModel) -> str:
    pairs = list(report.rows)
    for model_id in report.model_ids:
        pairs.append(("model_id", model_id))
    for attack_id in report.attack_ids:
        pairs.append(("attack_id", attack_id))
    rows = "\n".join(f"{latex_escape(k)} & {latex_escape(v)} \\\\" for k, v in pairs)
    return f"\\begin{{tabular}}{{ll}}\n\\hline\n{rows}\n\\hline\n\\end{{tabular}}\n"
