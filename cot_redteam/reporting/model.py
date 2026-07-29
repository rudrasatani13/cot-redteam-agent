"""Report view model."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from cot_redteam.core.types import EvaluationRun, JsonValue
from cot_redteam.eval.metrics import MetricSummary, summarize_run


@dataclass(frozen=True)
class ReportModel:
    run_id: str
    status: str
    planned: int
    succeeded: int
    failed: int
    cancelled: int
    monitor_excluded: int
    attack_success_rate: str
    evasion_rate: str
    provider_failure_rate: str
    monitor_failure_rate: str
    model_ids: tuple[str, ...]
    attack_ids: tuple[str, ...]
    monitor_ids: tuple[str, ...]
    config_digest: str | None
    dataset_digest: str | None
    limitations: tuple[str, ...]
    rows: tuple[tuple[str, str], ...]
    metrics: MetricSummary
    manifest: Mapping[str, JsonValue]

    @classmethod
    def from_run(
        cls,
        run: EvaluationRun,
        *,
        manifest: Mapping[str, JsonValue] | None = None,
    ) -> ReportModel:
        metrics = summarize_run(run)
        manifest = dict(manifest or {})

        def fmt_rate(rate: float | None) -> str:
            return "N/A" if rate is None else f"{rate:.3f}"

        model_ids = tuple(sorted({str(i.model) for i in run.items}))
        attack_ids = tuple(sorted({i.attack_id for i in run.items}))
        monitor_ids = tuple(sorted({o.monitor_id for i in run.items for o in i.monitors}))
        rows = (
            ("run_id", run.run_id),
            ("status", run.status.value),
            ("planned", str(run.summary.planned)),
            ("succeeded", str(run.summary.succeeded)),
            ("failed", str(run.summary.failed)),
            ("cancelled", str(run.summary.cancelled)),
            ("monitor_excluded", str(run.summary.monitor_excluded)),
            ("attack_success_rate", fmt_rate(metrics.attack_success.rate)),
            ("evasion_rate", fmt_rate(metrics.evasion.rate)),
            ("evasion_eligible", str(metrics.evasion.eligible)),
            ("evasion_excluded", str(metrics.evasion.excluded)),
            ("provider_failure_rate", fmt_rate(metrics.provider_failure_rate)),
            ("monitor_failure_rate", fmt_rate(metrics.monitor_failure_rate)),
            ("config_digest", run.config_digest or ""),
            ("dataset_digest", run.dataset_digest or ""),
        )
        raw_limits = manifest.get("limitations") or []
        if not isinstance(raw_limits, list):
            raw_limits = []
        limitations = tuple(str(x) for x in raw_limits)
        return cls(
            run_id=run.run_id,
            status=run.status.value,
            planned=run.summary.planned,
            succeeded=run.summary.succeeded,
            failed=run.summary.failed,
            cancelled=run.summary.cancelled,
            monitor_excluded=run.summary.monitor_excluded,
            attack_success_rate=fmt_rate(metrics.attack_success.rate),
            evasion_rate=fmt_rate(metrics.evasion.rate),
            provider_failure_rate=fmt_rate(metrics.provider_failure_rate),
            monitor_failure_rate=fmt_rate(metrics.monitor_failure_rate),
            model_ids=model_ids,
            attack_ids=attack_ids,
            monitor_ids=monitor_ids,
            config_digest=run.config_digest,
            dataset_digest=run.dataset_digest,
            limitations=limitations,
            rows=rows,
            metrics=metrics,
            manifest=manifest,
        )
