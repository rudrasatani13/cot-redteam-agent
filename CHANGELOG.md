# Changelog

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
