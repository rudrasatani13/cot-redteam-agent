# CoT Red Team Agent 0.3 Implementation Plan

**Goal:** Implement the approved model/API prompt-injection benchmark while
preserving the 0.2 configuration, CLI, provider, plugin, storage, and report
contracts.

**Design:** See
`docs/superpowers/specs/2026-07-29-cot-redteam-v0.3-benchmark-design.md`.

## Global constraints

- Keep existing 0.2 configurations and third-party attack/monitor plugins
  working.
- Treat scenarios, imported datasets, model responses, reasoning, and judge
  responses as hostile data.
- Do not execute dataset-provided code or use an unrestricted template engine.
- Do not count provider, scorer, judge, or monitor failures as secure results.
- Count every target and judge request against budgets.
- Preserve prompt, response, and reasoning retention before all persistence.
- Add behavior through tests first and keep the repository passing after each
  slice.

## Task 1: Messages, capabilities, and scenario schema

**Production areas:** `core/types.py`, new `benchmark/` package, configuration,
serialization, package data.

1. Add role-aware immutable messages and mutually exclusive legacy/message
   generation requests.
2. Add target capabilities and requirement validation.
3. Add strict scenario, policy, objective, technique, transform, and scorer
   specifications.
4. Add bounded, declarative template rendering with an allow-list.
5. Add JSONL suite loading, canonical digests, provenance, and license
   validation.

**Verification:** targeted schema, hostile-input, serialization, and existing
core tests; Ruff and mypy for changed modules.

## Task 2: Trial planning and repetitions

**Production areas:** benchmark planner, existing run planner compatibility,
configuration, budgets, manifests.

1. Expand model, scenario, policy, technique, transformation, and repetition
   matrices into stable trial IDs.
2. Validate target capabilities before execution.
3. Enforce maximum expansion and zero-eligible-trial errors.
4. Produce request and judge-call preflight bounds.
5. Keep the existing attack/sample planner unchanged for legacy runs.

**Verification:** deterministic matrix, unique IDs, compatibility rejection,
expansion limits, and budget preflight tests.

## Task 3: Conversation execution and providers

**Production areas:** provider protocol, OpenAI-compatible transport, Anthropic
transport, benchmark conversation runner, engine lifecycle.

1. Serialize ordered messages without silently dropping roles.
2. Add `openai_compatible` provider configuration and factory support.
3. Run fixed scripted turns while appending target responses to history.
4. Count and store each turn independently.
5. Preserve partial transcripts and typed failures.

**Verification:** HTTP mocks for roles and reasoning, scripted multi-turn
integration tests, per-turn budgets, retries, cancellation, and provider
lifecycle tests.

## Task 4: Policies, canaries, techniques, and transformations

**Production areas:** benchmark policy, canary, technique, and transform
modules; packaged profiles.

1. Package the four approved policy profiles.
2. Generate unpredictable multi-fragment canaries with an injectable
   deterministic test factory.
3. Implement approved direct, role, format, delimiter, multi-turn, document,
   and simulated-tool techniques.
4. Implement bounded deterministic text transformations.
5. Record versions, parameters, and digests.

**Verification:** no canary enters attacker-controlled text, transformation
determinism and bounds, safe rendering, and policy/technique compatibility
tests.

## Task 5: Scoring, utility, and metrics

**Production areas:** benchmark scorers, optional judge, metric summaries and
comparisons.

1. Add four-state scorer outcomes and eligibility.
2. Implement exact, normalized, partial, rogue-string, schema, overlap,
   completion, and false-refusal scorers.
3. Score final text and visible reasoning independently.
4. Add strict optional JSON judge parsing.
5. Add utility and false-refusal dimensions.
6. Add Wilson intervals and paired policy comparisons without introducing a
   universal security score.

**Verification:** quoted-refusal regression, complete/partial leak cases,
reasoning-only leak, judge failures, utility controls, denominators, and
interval tests.

## Task 6: Persistence, manifests, and reports

**Production areas:** SQLite migration, artifact manifests, report view model,
Markdown/CSV/LaTeX renderers, new JSONL renderer.

1. Add additive idempotent tables for trials, turns, and scorer outcomes.
2. Apply retention before storing every target and judge turn.
3. Record full trial provenance and capability adaptations.
4. Render per-trial evidence and grouped benchmark metrics.
5. Add a lossless canonical JSONL export.
6. Preserve reading and reporting existing 0.2 runs.

**Verification:** migration fixtures, idempotency, redaction, round trips,
manifest integrity, golden reports, and legacy-run compatibility.

## Task 7: Built-in suites and external adapters

**Production areas:** packaged benchmark data, suite registry, CLI import
commands, CyberSecEval and IH-Challenge adapters.

1. Add the 8-malicious/4-control smoke suite.
2. Add the 40-malicious/16-control core suite across eight families.
3. Validate positive objectives, controls, provenance, licenses, and duplicate
   digests.
4. Import supported CyberSecEval rows.
5. Import recognized IH-Challenge rows without executing grader code.
6. Report imported, skipped, and rejected rows with reasons.

**Verification:** clean-wheel loading, corpus invariants, inert grader-code
tests, path/size limits, and deterministic import manifests.

## Task 8: CLI, documentation, and release gates

**Production areas:** CLI, Python API, example configuration, README,
configuration/provider/experiment/plugin docs, migration guide, changelog,
release checklist, package version and data.

1. Add suite discovery, validation, display, and dataset-import commands.
2. Route benchmark configurations through the new planner and engine while
   preserving legacy `run`.
3. Document expected calls, cost controls, retention, interpretation, and
   limitations.
4. Add migration and authoring guides.
5. Update version and release artifacts only after all behavior is complete.

**Verification:** CLI and documented-example tests, Ruff format/check, mypy,
full pytest and coverage gates, build, lock verification, clean-wheel smoke,
and credential-gated live OpenAI-compatible smoke test when a key is
available.
