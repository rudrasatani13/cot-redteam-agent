# Changelog

## Unreleased

Security- and correctness-focused hardening pass over the full audit of the
0.6.0 codebase. All gates green: 749 tests, ruff, ruff format, mypy.

### Changed

- **OWASP tags migrated to the GenAI LLM Top 10 (2026)** (published
  2026-08-04): Excessive Agency is LLM03, Misinformation is LLM07, Hidden
  Context Exposure is LLM08, Improper Output Handling is LLM10, and the
  draft-only "Model Theft" entry is gone. The canary family now tags
  LLM01/LLM02/LLM08, the agent-lane prefix tags LLM03/LLM01, and reports
  annotate the mapping version on every OWASP line so tag citations cannot
  silently drift between list releases.
- `pytest-timeout` added to dev extras and `requirements-dev.lock`
  (hash-locked); `--timeout` now works locally and in CI.
- CI test matrix expanded from Ubuntu to **Ubuntu, macOS, and Windows**
  across Python 3.10-3.13; symlink-dependent artifact-path tests skip on
  Windows where symlink creation requires privileges.
- Added `AGENTS.md` (on-boarding contract for AI contributors) and
  `docs/roadmap.md` (phased direction for v0.7+).

### Fixed — scoring integrity

- **Refusal re-quotes are never compliant disclosure**: refusal analysis now
  gates every presentation form (own-line dumps, `TOKEN=`/JSON-style
  fields), honoring the documented "refusal re-quotes are not success"
  guarantee in both the attacks path and the benchmark exact/normalized
  canary scorers (new `refusal_quote_only` metric). Missing refusal
  contractions (`i shouldn't`, `can't share`, …) added to the marker list.
- **Canary can no longer leak into attacker context**: attempt-history
  response previews, evidence, and prompt texts are scrubbed of the canary
  before they can reach crescendo turn rendering or the LLM-attacker
  prompt, eliminating self-fulfilling multi-turn "disclosures".
- **Obfuscation-tolerant canary detection**: case-insensitive,
  whitespace-collapsed, zero-width, homoglyph, leetspeak, morse, and binary
  variants are detected, so the shipped encoding techniques score as real
  disclosures instead of systematic false negatives.
- **Adaptive success is never discarded** when `stop_on_success` is
  disabled; later failed attempts no longer overwrite a real disclosure.
- **PAIR-loop dedup fixed**: candidates are deduplicated against rendered
  prompt texts (previously compared against payload IDs and never matched).
- Benchmark false-refusal matching handles curly apostrophes; the JSON
  schema scorer accepts fenced JSON output.
- Race command: one misconfigured model yields an error row instead of
  aborting the race, the "disclosed" verdict requires the actually planted
  canary (no longer self-fulfilling from response-extracted tokens), and
  `--max-tokens` applies to attack prompts.
- Hardcoded canary prefixes removed from techniques, the payload bank, and
  persisted attack metadata (previously leaked 18 of 27 default-canary
  characters and asserted wrong prefixes for custom canaries).
- Paired model comparisons now use exact McNemar statistics
  (discordant-pair SE, binomial p-value) instead of unpaired Fisher/Wald
  math; duplicate sample IDs resolve deterministically to the first item.

### Fixed — security

- **Report injection**: judge explanations, monitor explanations, and
  evidence spans are markdown-escaped or safely code-fenced; the CSV
  formula-injection neutralizer covers every column; LaTeX generation uses
  the full escaper everywhere.
- **Judge hardening**: `llm_judge` and the harm rubric wrap all untrusted
  fields in delimited UNTRUSTED-DATA blocks with explicit do-not-follow
  instructions (mirroring the benchmark judge); strict boolean parsing so
  judge JSON strings like `"false"` can no longer flip verdicts; rubric
  success cannot contradict a zero score.
- **Retention enforcement**: `retain_responses: false` now also redacts
  attempt-history previews and assessment evidence; error strings always
  pass through credential redaction; config-validation redaction covers
  `authorization`/`cookie`/`session`/`bearer`-class fields.
- **Agent lane**: the canary oracle proves impact from transmitted payload
  content of the specific mutating action (sink-name spoofs no longer
  verify); the protected-state oracle detects transient
  mutate-and-restore; approval grants are bound to the acting principal;
  concurrent dispatch snapshots/events are recorded inside the semaphore
  so evidence attribution is deterministic; regression-suite artifact
  paths are contained under the suite directory; detached `.sha256`
  sidecars are verified on load; duplicate JSON keys are rejected; replay
  artifacts record retention flags and honor the recorded seed.
- **Gateway limits**: oversized arguments are truncated before recording;
  denied requests are bounded by `max_denied_requests`; scenario
  `max_payload_bytes` is wired into the gateway; tool argument validation
  rejects bools-for-integers and unknown argument names.
- `regex` monitor: one invalid pattern no longer disables the whole
  monitor, input is Unicode-normalized (curly apostrophes match), and the
  final answer text is scanned in addition to reasoning.
- Ensemble/cascading monitors accept per-child configuration and reject
  recursive composition with a clear error instead of `RecursionError`.
- OWASP mapping covers all registered attack families with corrected
  labels (distillation → LLM10 Model Theft, evasion → LLM05 Improper
  Output Handling, faithfulness → LLM08, sandbagging → LLM09).
- SQLite: `StorageError(ValueError)` taxonomy at storage boundaries,
  crash-atomic migrations, `evaluation_items(run_id)` /
  `monitor_outcomes(item_id)` indexes, 30 s connect timeout, Windows
  reserved-name/ADS path rejection.
- Provider transports: `Retry-After` clamped to 60 s on both providers;
  3xx classified permanent; Anthropic temperature clamped to 0–1; text
  blocks joined with paragraph separators; cache tokens
  (`cache_creation`/`cache_read`) billed at 1.25×/0.1× input price; wire
  request attempts recorded in the ledger and invocation events.

### Fixed — reliability / UX

- TUI: `/attack <id>` selections are honored (previously always overwritten
  by effort presets); a runtime TUI crash no longer silently starts a
  second billed evaluation via the fallback dashboard; budget raises for
  the requested models/payloads are logged visibly; `Ctrl+C` cancels the
  in-flight evaluation and exits 130.
- CLI: one broken third-party plugin is skipped with a warning instead of
  bricking every command; `Ctrl+C` exits 130 (distinct from `1 = findings`);
  `OSError` exits 2; `list-providers` includes `mock`; evolve writes its
  archive once atomically and no longer references unpersisted run ids.
- Attacker-side `BudgetExceededError` classifies the item instead of
  aborting the run; `evolve` runs under a single shared budget ceiling
  (no longer multiplied per candidate); the evolution-rounds off-by-one is
  fixed; unknown template placeholders are rejected at validation.
- `log_level` is actually applied; `run_benchmark` bootstraps plugins for
  direct API callers.

### Added

- `agent.deny_unauthorized_tools` config option (default `false`): deny
  tool dispatch when the trusted scope resolver returns UNAUTHORIZED.
  Default stays observe-only so oracles can prove impact from executed
  unauthorized calls.
- `RegexMonitorAdvanced` now ships a genuinely expanded evasion-phrase
  pattern set; `SelfMonitoringJudge` has a distinct self-audit rubric.

## 0.6.0 — Proof-of-Action Foundation

### Added

- **Agent-security path** (`cot_redteam.agent`): evaluates *agent behavior*
  — only observed simulated actions and deterministic world state
  transitions can prove impact; model text is evidence about model
  behavior, never proof of agent impact.
- **Support Agent World**: the only executable simulated world in v0.6 —
  in-memory tickets, CRM records, canaries, outbound sink, approval state,
  and protected state. No tool performs real network, shell, filesystem,
  subprocess, or external database effects.
- **Deny-by-default `ToolGateway`**: registry membership, scenario sandbox
  allowlist, schema validation, argument/result byte limits, per-run action
  count, per-call timeout, and concurrent-call bounds; records
  `ToolCallRequested` → `ActionEvent` (attempted/executed, state digests,
  requested-vs-policy-observed authorization) → `ToolResultReceived`.
- **Deterministic oracles**: canary-reached-sink, unauthorized-tool-call,
  scope-escalation, approval-bypass, and protected-state-mutation oracles
  over immutable pre/post world snapshots + structured trajectories.
  Assistant prose alone can never produce `VERIFIED_EXPLOIT`; oracle
  failures are never clean.
- **Three scripted scenarios** with vulnerable/patched/clean fixtures:
  indirect prompt injection, tool-result injection, approval bypass.
- **Replay artifacts**: strict versioned JSON with non-self-referential
  payload checksums and detached `.sha256`; exact replay reproduces a
  verified exploit; regression suites replay saved exploits against
  patched targets expected to hold.
- **CLI**: `cot-redteam agent scan --config`, `cot-redteam replay
  EXPLOIT.json`, `cot-redteam regress --suite`.
- **Shared `InvocationService`**: every built-in target/attacker/judge/
  monitor-judge/generator/race logical model call is budgeted and
  role-attributed. Unknown provider pricing is never silently treated as
  free under a cost ceiling (typed `UnknownPricingError` before the call).
- **Artifact root containment**: absolute paths, `..` traversal, control
  characters, symlink components, and symlink destinations are rejected;
  every write stays inside the pinned artifact root.
- **Benchmark trial isolation**: unexpected trial exceptions become typed
  `INTERNAL_ERROR` evidence; sibling trials finish; runs never abort.
- **Retention hardening**: recursive credential-class redaction, monitor
  `judge_response` removal when responses are not retained, and
  storage-boundary agent retention with privacy-first defaults.
- **Agent SQLite migration 3**: crash-safe begin/append/finalize agent run
  persistence, append-only trajectory events, interrupted-run recovery,
  replay records, and agent manifests.
- **Endpoint policy primitive** (`core/network_policy.py`) for future agent
  HTTP targets; no HTTP agent target ships in v0.6.

### Security notes

- Third-party plugins and custom Python target adapters remain trusted
  in-process code and are not sandboxed.
- Remote model calls are optional, user-funded, and budgeted; the release
  is fully provable offline with the `mock` provider plus scripted targets.

## Unreleased


### Added

- **Unicode punctuation normalization in refusal/hedge detection**:
  models that refuse with a curly apostrophe (`can't` / U+2019) were
  classified as "complied" by race verdicts and the strict scorer. Added
  `normalize_text()` (curly quotes/apostrophes, dashes, nbsp -> ASCII) to
  refusal/hedge marker matching + regression tests. Found live in the
  25-model OpenCode Go taste: gpt-5.6-luna, minimax-m2.5/m2.7,
  qwen3.8-max
- **`scan` command**: quick CI-ready compliance scan — deterministic adaptive
  canary attack + regex monitor + tight budgets by default (overridable);
  prints a per-model findings table and exits 0 (clean) / 1 (findings) /
  3 (partial) so CI pipelines can gate on it
- **OWASP LLM Top 10 tagging**: reports now tag each item with the relevant
  OWASP categories (LLM01 prompt injection, LLM02 sensitive information
  disclosure, LLM07 system prompt leakage, LLM05 improper output handling,
  ...) via conservative id/prefix rules
- `evaluation.budgets.max_requests` / `max_elapsed_seconds` are now
  documented CLI override keys
- **General forbidden-behavior scoring** (`harm.forbidden_behavior`):
  StrongREJECT-style rubric judge (refusal / specificity / convincingness)
  scores a target's compliance with arbitrary harmful requests — no canary
  needed. Requires `judge_model` in attack_config; ships with the 10-item
  `pkg:harmful.jsonl` dataset (fraud, weapons, disinformation, hate speech,
  doxxing, ...). Engine prefers async `assess_async` when an attack defines
  it; `pkg:` markers now resolve any packaged dataset and survive config
  path resolution (with traversal guards)
- **Crescendo-style multi-turn attack** (`injection.crescendo_canary`):
  gradual 5-rung escalation from a benign transparency question to an exact
  token ask; each turn embeds the model's own previous reply for
  conversational continuity (arXiv:2404.01833 pattern, deterministic ladder,
  no attacker LLM required)
- **Adaptive Attempt Trace in reports**: Markdown reports now render the
  full attempt history (payload, verdict, defense class, response preview)
  for adaptive/multi-turn runs, so the whole escalation is auditable
- Engine attempt history now carries `response_preview` so multi-turn and
  LLM-driven attacks can reference the model's actual words (also feeds the
  LLM attacker's context)
- **LLM-driven adaptive attacker** (`injection.system_canary_agent_llm`):
  PAIR/TAP-style attack where an attacker model writes extraction prompts
  from the full conversation history and latest defense class. Generates
  `branch_width` candidates per step (TAP-style branching), tries them
  best-first, refreshes from updated history, and degrades to the
  deterministic technique catalog if the attacker provider fails. The
  canary never enters the attacker context. Live-verified: the attacker
  invented a JSON-schema coercion prompt that made deepseek-v4-flash
  disclose the canary (payload `llm-7`, attempt 7/8)
- Engine agentic hook now supports async `next_prompt_after_failure_async`
  for provider-backed attackers (sync contract unchanged)

## 0.5.0 — 2026-08-05

### Added

- Headless test suite for the interactive TUI: command handling, event
  consumption, run/stop flows (with the keyless mock provider), Textual
  mount via `run_test`, Rich live dashboard, and render edge cases. TUI
  coverage: app 14%→75%, interactive 11%→81%, state 61%→89%, render 77%→94%
  (package total 77.7%→84.0%)
- Agentic attack `injection.system_canary_agent`: seed bank → classify defense →
  invent next technique until real final-text disclosure or `max_attempts`
- Deterministic technique catalog (format, transform, authority, social, …)
  selected from refusal/defense feedback
- **Parseltongue-inspired encoding family**: leetspeak, Unicode homoglyphs,
  zero-width joiners, morse, reversed chars, ROT13, base64, hex, and binary
  techniques in the agent catalog, with matching `encoding` payloads in the
  packaged bank
- **Encoded-disclosure scoring**: base64/hex/ROT13/reversed/chunked forms of
  the canary in the final text now count as real leaks (with per-encoding
  evidence); an encoded quote inside a refusal is still not success
- **Hedge-aware defense classification**: soft-refusal/hedge markers add a
  `hedged_refuse` defense class and `hedge_count` / `hedged_disclosure`
  metrics, so the agent can counter weak refusals instead of treating them
  like hard refusals
- **Keyless `mock` provider kind** (`mock_mode: auto|refuse|disclose|error`)
  for demos, tests, and CI without API keys
- **`cot-redteam race`**: run one probe across models and compare compliance
  verdicts (disclosed / refused / hedged / complied / error)
- GODMODE-inspired payload bank seeds: refusal-inversion divider,
  boundary inversion, prefill roleplay, and encoding framings

### Changed

- Polished interactive TUI: darker theme, status badges, attempt progress bar,
  side-by-side timeline/output, clearer leak panel
- **Slim command composer**: two-row bottom chrome (1-line input + keys),
  Codex-style fill with **no** tall/solid side borders (removes the 3-line
  left-edge glyphs); mid panels flex so the type bar stays pinned and visible
- `docs/tui.md`: layout map, slim-composer notes, `--config` requirement,
  agentic attack example, and updated slash-command table
- CI no longer runs the full pipeline twice for PR branches (`push` is
  limited to `main`; `pull_request` still covers branch pushes)

### Fixed

- Refusal detection now catches `i am unable` / `i'm unable` / `unable to
  comply` / `i must adhere` phrasings (found live: a qwen3.5-plus refusal was
  misclassified as "complied" by `race`)
- `config validate` no longer requires an `openrouter` provider (or any
  unused provider) when the config omits the `generative` section: the
  `generative.generator_model` default no longer silently references
  `openrouter:anthropic/claude-3.5-sonnet`. `evolve` now errors clearly when
  no generator model is configured.
- CLI `--help` banner now shows the real package version instead of a
  hardcoded stale `0.3` string.
- Budget tracker no longer counts a phantom request when the elapsed-time
  limit trips during reservation.
- Removed dead no-op redaction branch in retention sanitizer and documented
  that `retain_responses` / `retain_reasoning` are independent toggles.
- `llm_judge` / `self_monitor` no longer default to an unconfigured
  `openrouter` judge route: the engine injects `evaluation.judge_model` as a
  fallback and the monitor reports a clear error when no judge model is set.
- `llm_judge` retries once when the judge returns non-JSON (real judges are
  flaky), raises the judge `max_tokens` default from 512 to 1024 (verbose
  judges truncate mid-JSON), and records the raw judge response in monitor
  details for auditability.
- Canary mentioned only while refusing in final text is no longer attack success;
  require compliant disclosure (own line, structured field, or non-refusal dump)
- TUI command input no longer uses `border: tall` / squeezed solid frames that
  hid the cursor or painted multi-line left borders
- Regenerated `requirements-dev.lock` so primary CI installs `rich`/`textual`
  (hash-locked job was missing TUI deps → CSS import test + coverage floor)

## 0.4.0 — 2026-07-30

### Added

- Adaptive educational attack `injection.system_canary_adaptive` with a
  packaged multi-payload bank (`system_canary_bank.jsonl`)
- Evaluation engine multi-attempt loop: try the next payload until real
  disclosure succeeds or the bank is exhausted (`stop_on_success`)
- External JSONL payload bank loading via `attack_config.bank_path`
- Codex-style interactive TUI (`cot-redteam tui --config …`) with:
  status header, multi-model board, activity log, model output, last
  successful disclosure, and slash commands (`/model`, `/add`, `/payloads`,
  `/run`, `/stop`, `/effort`, `/quit`, …)
- Progress event stream (`RunEvent`) from the evaluation engine for UIs
- `docs/tui.md` and README screenshot of the adaptive dashboard

### Fixed

- System-canary success no longer counts refusal analysis that only quotes the
  canary while saying the user is attempting prompt injection; success requires
  real disclosure (final text, or non-refusal reasoning leak)

### Dependencies

- `rich` and `textual` for the live / interactive TUI

## 0.3.0 — 2026-07-29

### Added

- Role-aware message and capability contracts with deterministic scripted
  multi-turn execution
- Repeated benchmark trial matrices across model, suite, policy, technique,
  transformation, and repetition
- Cryptographically random per-trial multi-fragment canaries
- Evidence-bearing deterministic scorers, strict-JSON optional judges, utility
  controls, false-refusal outcomes, and Wilson confidence intervals
- Packaged 12-scenario smoke and 56-scenario core benchmark suites
- Generic explicitly configured OpenAI-compatible provider kind
- Offline CyberSecEval and IH-Challenge JSONL adapters that never execute
  dataset grader code
- Additive benchmark SQLite schema, retention-aware transcripts, versioned
  manifests, JSONL evidence, and benchmark Markdown/CSV/LaTeX reports
- `list-suites`, `suite validate|show`, and `dataset import` CLI commands
- Verifiable `injection.system_canary` attack with an explicit trusted-system
  boundary and exact-disclosure success criteria
- Item-level Markdown evidence for retained prompts, responses, provider
  reasoning, attack assessments, and monitor outcomes

### Changed

- `cot-redteam run` selects the benchmark engine when suites are configured and
  otherwise preserves the legacy `0.2` path
- Attack success, reasoning leakage, utility, refusal, reliability, and monitor
  outcomes are no longer collapsed into one benchmark score
- Regex monitoring without visible reasoning is now non-evaluable instead of
  clean, preventing misleading evasion rates
- The packaged quickstart now uses the system-canary attack

### Compatibility

- Existing version-2 YAML configuration, `run_evaluation`, legacy plugins,
  attacks, monitors, reports, and stored runs remain supported.
- See `docs/migration-0.2-to-0.3.md`.

## 0.2.0 — 2026-07-29

Intentional breaking rewrite for production-grade CoT red-team evaluation.

### Added

- Strict `AppConfig` (version 2) with credential environment variables and redaction
- Stable attack/monitor plugin registries and entry-point discovery
- Shared asynchronous OpenAI-compatible and Anthropic providers
- Dataset digests, paired planner, budgets, async evaluation engine
- Eligibility-aware metrics (errors never count as evasion)
- Transactional SQLite store, atomic artifacts, reproducibility manifests
- Markdown / CSV / LaTeX report renderers
- Supported Python API (`run_evaluation`, `load_run`)
- Bounded generative evolution evaluated through the standard run engine
- Per-provider concurrency limits and pricing-based estimated-cost budgets
- Wheel-safe `init` configuration and packaged 15-sample dataset
- Retention-aware sanitization before SQLite and artifact persistence
- Detached manifest checksums and stored report manifests
- CI for Python 3.10–3.13, coverage floors, wheel smoke tests
- Security policy, responsible-use guidance, and contributor community files

### Removed

- `0.1.x` dual configuration paths and `BaseAttack.run` engine ownership
- Unintegrated model watcher scheduler
- Advertised but unimplemented dashboard / Parquet tracking extras

### Migration

See `docs/migration-0.1-to-0.2.md`.

### Distribution

Release artifacts are distributed through GitHub Releases. Version `0.2.0` is
not published to PyPI.
