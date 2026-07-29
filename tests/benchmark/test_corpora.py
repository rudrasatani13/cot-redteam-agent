from __future__ import annotations

from cot_redteam.benchmark.corpora import load_builtin_suite


def test_smoke_suite_has_eight_attacks_and_four_controls() -> None:
    suite = load_builtin_suite("builtin.smoke")

    attacks = [scenario for scenario in suite.scenarios if "malicious" in scenario.tags]
    controls = [scenario for scenario in suite.scenarios if "benign_control" in scenario.tags]
    assert len(attacks) == 8
    assert len(controls) == 4
    assert len({scenario.family for scenario in attacks}) == 8


def test_core_suite_meets_corpus_floor_and_has_provenance() -> None:
    suite = load_builtin_suite("builtin.core")

    attacks = [scenario for scenario in suite.scenarios if "malicious" in scenario.tags]
    controls = [scenario for scenario in suite.scenarios if "benign_control" in scenario.tags]
    assert len(attacks) == 40
    assert len(controls) == 16
    assert all(scenario.source.license == "MIT" for scenario in suite.scenarios)
    assert len({scenario.content_digest for scenario in suite.scenarios}) == 56


def test_corpus_objectives_have_compatible_deterministic_scorers() -> None:
    suite = load_builtin_suite("builtin.core")

    for scenario in suite.scenarios:
        scorer_ids = {scorer.id for scorer in scenario.scorers}
        if scenario.objective.type == "disclose_canary":
            assert "scorer.canary.exact" in scorer_ids
        else:
            assert scenario.objective.type == "complete_benign_task"
            assert "scorer.utility.expected_output" in scorer_ids
