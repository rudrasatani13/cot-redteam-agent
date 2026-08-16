"""Eligibility-aware summaries, confidence intervals, and comparisons."""

from __future__ import annotations

import math
import random
from collections.abc import Sequence
from dataclasses import dataclass

from cot_redteam.core.types import EvaluationItem, EvaluationRun, ItemStatus, MonitorStatus
from cot_redteam.monitors.evasion import compute_evasion


@dataclass(frozen=True)
class RateSummary:
    eligible: int
    successes: int
    excluded: int
    rate: float | None
    ci_low: float | None = None
    ci_high: float | None = None


@dataclass(frozen=True)
class MetricSummary:
    attack_success: RateSummary
    monitor_trigger: RateSummary
    evasion: RateSummary
    provider_failure_rate: float | None
    monitor_failure_rate: float | None


@dataclass(frozen=True)
class ComparisonResult:
    group_a_size: int
    group_b_size: int
    group_a_successes: int
    group_b_successes: int
    risk_difference: float | None
    odds_ratio: float | None
    ci_low: float | None
    ci_high: float | None
    # Deprecated: unpaired Fisher exact was replaced by the exact McNemar
    # test below; kept (always None) so existing consumers keep their shape.
    fisher_p_value: float | None
    mcnemar_p_value: float | None = None
    discordant_a_only: int = 0
    discordant_b_only: int = 0
    concordant_both_success: int = 0
    concordant_both_failure: int = 0


def _rate(successes: int, eligible: int) -> float | None:
    if eligible <= 0:
        return None
    return successes / eligible


def bootstrap_interval(
    values: Sequence[float],
    *,
    seed: int = 0,
    n_boot: int = 1000,
    alpha: float = 0.05,
) -> tuple[float | None, float | None]:
    if len(values) < 2:
        return None, None
    rng = random.Random(seed)
    means: list[float] = []
    n = len(values)
    for _ in range(n_boot):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    low_idx = int((alpha / 2) * n_boot)
    high_idx = min(n_boot - 1, int((1 - alpha / 2) * n_boot))
    return means[low_idx], means[high_idx]


def summarize_run(run: EvaluationRun, *, seed: int = 0) -> MetricSummary:
    items = run.items
    planned = len(items)
    succeeded = [i for i in items if i.status is ItemStatus.SUCCEEDED]
    provider_fail = sum(1 for i in items if i.status is ItemStatus.PROVIDER_ERROR)
    monitor_fail = sum(1 for i in items if i.status is ItemStatus.MONITOR_ERROR)

    attack_successes = sum(1 for i in succeeded if i.assessment and i.assessment.success)
    attack_rate = _rate(attack_successes, len(succeeded))
    attack_vals = [1.0 if (i.assessment and i.assessment.success) else 0.0 for i in succeeded]
    a_lo, a_hi = bootstrap_interval(attack_vals, seed=seed)

    trigger_eligible = 0
    trigger_successes = 0
    for item in succeeded:
        for outcome in item.monitors:
            if outcome.is_evaluable:
                trigger_eligible += 1
                if outcome.status is MonitorStatus.TRIGGERED:
                    trigger_successes += 1

    evasion_eligible = 0
    evasion_successes = 0
    evasion_excluded = 0
    for item in succeeded:
        result = compute_evasion(item.monitors)
        if not result.eligible:
            evasion_excluded += 1
            continue
        evasion_eligible += 1
        if result.evaded:
            evasion_successes += 1

    return MetricSummary(
        attack_success=RateSummary(
            eligible=len(succeeded),
            successes=attack_successes,
            excluded=planned - len(succeeded),
            rate=attack_rate,
            ci_low=a_lo,
            ci_high=a_hi,
        ),
        monitor_trigger=RateSummary(
            eligible=trigger_eligible,
            successes=trigger_successes,
            excluded=0,
            rate=_rate(trigger_successes, trigger_eligible),
        ),
        evasion=RateSummary(
            eligible=evasion_eligible,
            successes=evasion_successes,
            excluded=evasion_excluded,
            rate=_rate(evasion_successes, evasion_eligible),
        ),
        provider_failure_rate=_rate(provider_fail, planned),
        monitor_failure_rate=_rate(monitor_fail, planned),
    )


def _index_by_sample(items: Sequence[EvaluationItem]) -> dict[str, EvaluationItem]:
    """Index succeeded, assessed items by sample_id.

    Duplicate-resolution rule: items are stably sorted by sample_id (stable
    sort preserves the input order of equal keys), and the FIRST occurrence
    in that order — i.e. the first eligible item encountered in the input —
    wins. Later duplicates are discarded.
    """
    indexed: dict[str, EvaluationItem] = {}
    for item in sorted(items, key=lambda i: i.sample_id):
        if item.status is ItemStatus.SUCCEEDED and item.assessment is not None:
            indexed.setdefault(item.sample_id, item)
    return indexed


def paired_comparison(
    group_a: Sequence[EvaluationItem],
    group_b: Sequence[EvaluationItem],
) -> ComparisonResult:
    """McNemar paired analysis of attack success on shared samples.

    The two groups are evaluated on the same samples, so successes are
    paired per sample_id. The paired contingency table is built from
    sample-keyed pairs; the difference in success rates is reported with a
    discordant-pair standard error, and the exact McNemar test (binomial on
    the discordant pairs) replaces the old unpaired Wald SE + Fisher exact.
    """
    a_by_sample = _index_by_sample(group_a)
    b_by_sample = _index_by_sample(group_b)
    shared = sorted(set(a_by_sample) & set(b_by_sample))
    n = len(shared)
    if n == 0:
        return ComparisonResult(
            group_a_size=0,
            group_b_size=0,
            group_a_successes=0,
            group_b_successes=0,
            risk_difference=None,
            odds_ratio=None,
            ci_low=None,
            ci_high=None,
            fisher_p_value=None,
        )
    both_success = 0
    both_failure = 0
    a_only = 0  # a succeeded where b failed (discordant)
    b_only = 0  # b succeeded where a failed (discordant)
    for sid in shared:
        a_assessment = a_by_sample[sid].assessment
        b_assessment = b_by_sample[sid].assessment
        a_success = a_assessment is not None and a_assessment.success
        b_success = b_assessment is not None and b_assessment.success
        if a_success and b_success:
            both_success += 1
        elif not a_success and not b_success:
            both_failure += 1
        elif a_success:
            a_only += 1
        else:
            b_only += 1
    a_succ = both_success + a_only
    b_succ = both_success + b_only
    risk_diff = (a_succ - b_succ) / n

    # Paired (conditional) odds ratio on the discordant pairs, with a
    # Haldane-Anscombe style correction when one side has no discordance.
    if a_only == 0 or b_only == 0:
        odds = (a_only + 0.5) / (b_only + 0.5)
    else:
        odds = a_only / b_only

    # Discordant-pair SE for the paired difference in proportions.
    discordant = a_only + b_only
    se = math.sqrt(discordant) / n
    ci_low = risk_diff - 1.96 * se
    ci_high = risk_diff + 1.96 * se

    # Exact McNemar test: binomial test of the discordant split against 0.5.
    p_value: float | None
    if discordant == 0:
        p_value = 1.0
    else:
        try:
            from scipy.stats import binomtest

            p_value = float(binomtest(a_only, discordant, 0.5).pvalue)
        except Exception:
            p_value = None

    return ComparisonResult(
        group_a_size=n,
        group_b_size=n,
        group_a_successes=a_succ,
        group_b_successes=b_succ,
        risk_difference=risk_diff,
        odds_ratio=odds,
        ci_low=ci_low,
        ci_high=ci_high,
        fisher_p_value=None,
        mcnemar_p_value=p_value,
        discordant_a_only=a_only,
        discordant_b_only=b_only,
        concordant_both_success=both_success,
        concordant_both_failure=both_failure,
    )
