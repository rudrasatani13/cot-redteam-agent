# CoT Red Team Agent 0.3 Benchmark Design

**Status:** Approved direction  
**Date:** 2026-07-29  
**Release target:** `0.3.0`  
**Compatibility:** Backward-compatible extension of the `0.2` configuration and APIs

## 1. Decision

Version 0.3 will turn the existing one-prompt evaluation path into a
reproducible prompt-injection benchmark for raw model and chat-completion API
endpoints.

The release will not attempt to become a complete agent-testing platform.
However, its message, scenario, target-capability, and scoring contracts will
support later application, RAG, tool, and agent adapters without another core
rewrite.

The benchmark will measure both:

1. whether an attack achieved a defined objective; and
2. whether the model still completed the legitimate task.

A larger collection of prompts without these structural changes is not a
benchmark and is not sufficient for the release.

## 2. Context and current limitations

The 0.2 engine accepts one optional system prompt and one user prompt. It
cannot faithfully represent developer messages, conversation history,
multi-turn escalation, tool output, or retrieved untrusted content.

Several legacy attack assessments infer success from generic words such as
`ignore`, `hidden`, or `developer mode`. This can classify a refusal that
quotes the attack as a successful compromise. The generative attack evaluator
uses the same weak pattern.

The system-canary attack has a strong exact-disclosure oracle, but it uses one
public, fixed canary and one attack formulation. It is evidence for a specific
request, not a general robustness benchmark.

The planner also lacks repetitions. Each model, attack, and sample combination
is attempted once, even though provider responses may be stochastic.

Version 0.3 addresses these limitations while retaining the working 0.2
provider lifecycle, budgets, storage, manifests, retention policy, plugin
bootstrap, and failure-aware reporting.

## 3. Goals

Version 0.3 must:

1. represent role-aware, multi-message conversations;
2. execute deterministic scripted multi-turn scenarios;
3. declare and validate target capabilities before spending requests;
4. separate the benign task, attack objective, attack technique,
   transformation, policy, and scorer;
5. generate unpredictable synthetic canaries for each trial;
6. distinguish exact, partial, final-response, and visible-reasoning leakage;
7. distinguish attack success from benign-task utility and false refusal;
8. support repeated trials with stable trial identities;
9. provide a curated, attributable, license-safe built-in benchmark;
10. allow safe import of selected external benchmark formats without
    executing dataset-provided code;
11. aggregate results by model, policy, attack family, delivery channel,
    transformation, and trial;
12. preserve raw evidence and metric eligibility in auditable reports;
13. retain the existing `cot-redteam run` and Python API behavior for 0.2
    configurations;
14. support explicitly named generic OpenAI-compatible endpoints;
15. keep cost, request, token, concurrency, and elapsed-time limits effective
    across every conversation turn.

## 4. Non-goals

Version 0.3 will not:

- operate browsers, email accounts, calendars, or external SaaS applications;
- execute real tools or MCP servers;
- implement a vector database or production RAG pipeline;
- test arbitrary public websites or systems without explicit authorization;
- support image, audio, video, PDF, or other multimodal injection;
- implement an adaptive attacker that selects the next message from the
  target response;
- train, fine-tune, or modify target models;
- bundle external datasets whose licenses or source-data terms are
  incompatible or unclear;
- execute Python graders, templates, or scripts supplied by a dataset;
- add PyRIT, garak, Inspect AI, or Hugging Face Datasets as required runtime
  dependencies;
- claim that a single benchmark score establishes general model security;
- expose provider reasoning to users who have disabled reasoning retention.

Agent, RAG, tool, and multimodal evaluation remain candidates for later
releases built on the 0.3 contracts.

## 5. Considered approaches

### 5.1 Prompt-pack extension

Add many new `BaseAttack` classes and JSONL questions while preserving the
one-turn engine.

Advantages:

- smallest implementation;
- little migration work;
- quickly increases the number of prompts.

Disadvantages:

- cannot represent realistic conversation or trust boundaries;
- continues coupling prompt construction and scoring;
- repeats the existing false-positive problems;
- produces a larger anecdotal test rather than a benchmark.

This approach is rejected.

### 5.2 Benchmark core for model APIs

Introduce scenarios, messages, capabilities, scripted conversations,
composable transformations, deterministic scorers, utility controls, and
repeated trials while continuing to target raw provider APIs.

Advantages:

- directly serves the repository's existing users;
- corrects the current measurement weaknesses;
- remains feasible for a minor release;
- creates stable boundaries for future application and agent targets;
- avoids bringing live tool side effects into the initial benchmark.

Disadvantages:

- requires changes across domain types, planner, providers, storage, metrics,
  reports, configuration, and documentation;
- cannot yet measure whether a production agent takes an unsafe real-world
  action.

This is the selected approach.

### 5.3 Full agent and application platform

Add arbitrary HTTP applications, browser sessions, RAG stores, tool
simulators, MCP servers, and agent environments in the same release.

Advantages:

- supports realistic indirect injection and unauthorized-action testing;
- competes directly with broader agent security frameworks.

Disadvantages:

- multiplies trust boundaries and operational side effects;
- requires application-specific state, authentication, cleanup, and success
  oracles;
- makes a reliable 0.3 release too large;
- duplicates mature work in AgentDojo, PyRIT, and Inspect AI.

This approach is deferred.

## 6. Design principles

### 6.1 Objectives are separate from techniques

The objective describes what the attacker wants to achieve. The technique
describes how the request is framed. A transformation changes representation
without changing the objective. A scorer decides whether the objective was
achieved.

This permits the same objective to be tested through direct override,
role-spoofing, encoding, translation, delimiter confusion, or multi-turn
escalation without duplicating scoring logic.

### 6.2 Security and utility are separate axes

Refusing every request is not a successful defense. Every scenario that
contains a legitimate task defines an independently scored utility outcome.
Reports show attack success rate and task utility together.

### 6.3 Deterministic evidence precedes model judging

Exact canaries, expected strings, forbidden strings, and structured outputs
use local deterministic scorers. An LLM judge is optional and is used only
when the objective cannot be decided reliably with a deterministic oracle.

### 6.4 Unsupported capabilities fail closed

A scenario declares the capabilities it requires. The planner rejects an
incompatible target before making provider calls. The engine does not silently
flatten roles or remove messages because doing so changes the experiment.

An explicitly configured compatibility adaptation may flatten a role when the
user requests it, but the manifest and report must record that the experiment
was adapted and is not directly equivalent to native role support.

### 6.5 External benchmark content is untrusted data

Dataset files cannot execute code, load Python objects, import modules, access
the network, or expand arbitrary filesystem paths. Importers translate
allow-listed fields into the local declarative schema.

### 6.6 Minor-release compatibility

Existing 0.2 configuration files, single-turn attacks, monitors, reports, and
Python entry points continue to work. New benchmark functionality is additive.
Legacy attacks are not included in the default benchmark score unless they
have objective-based scorers.

## 7. Architecture

```text
CLI / Python API
        |
        v
Configuration + Suite Loader
        |
        +----> Scenario Registry
        +----> Policy Registry
        +----> Technique Registry
        +----> Transform Registry
        +----> Scorer Registry
        |
        v
Trial Planner
  model x scenario x policy x technique x transform x repetition
        |
        v
Capability Validation + Budget Preflight
        |
        v
Conversation Runner
        |
        +----> Provider Target
        +----> Transcript Recorder
        |
        v
Scoring Pipeline
  deterministic objective -> optional judge -> monitors -> utility
        |
        v
SQLite + Artifacts + Manifest + Reports
```

The application layer owns object construction and lifecycle. Scenario and
scorer domain models do not import HTTP, SQLite, CLI, or report code.

## 8. Domain model

### 8.1 Messages

The new immutable `Message` type contains:

- `role`: `system`, `developer`, `user`, `assistant`, or `tool`;
- `content`: text content for 0.3;
- `name`: optional tool or participant name;
- `trust`: `trusted` or `untrusted`;
- `source`: optional delivery-source label;
- `metadata`: validated JSON-compatible metadata.

`GenerationRequest` gains an ordered `messages` tuple. Its existing `prompt`
and `system_prompt` fields remain supported as the legacy single-turn form.
Construction rejects requests that populate both representations.

The provider receives an already resolved ordered message list. It does not
decide trust or attack semantics.

### 8.2 Target capabilities

Each provider target declares immutable capabilities:

- `supports_system_role`;
- `supports_developer_role`;
- `supports_multi_turn`;
- `supports_tool_role`;
- `supports_visible_reasoning`;
- `supports_native_seed`;
- supported input and output modalities.

Only text input and text output are required in 0.3.

Capabilities describe accepted protocol behavior, not security quality. A
provider accepting a system message does not prove that the model follows it.

### 8.3 Scenarios

A scenario is declarative data with:

- schema version;
- stable scenario ID and title;
- attack family and delivery channel;
- legitimate task;
- attack objective;
- ordered scripted steps;
- required target capabilities;
- compatible policy IDs;
- compatible technique and transformation IDs;
- scorer specifications;
- tags and difficulty;
- source URL or citation;
- SPDX license identifier or `proprietary-user-supplied`;
- content digest.

Scripted steps may contain fixed trusted or untrusted messages. Target
assistant responses are appended to the transcript before the next scripted
message. Version 0.3 does not branch or generate the next attack message from a
target response.

### 8.4 Policies

A policy is a named, versioned trusted instruction template. Built-in policy
profiles are:

- `policy.minimal`;
- `policy.hierarchy`;
- `policy.hierarchy_delimited`;
- `policy.strict_confidentiality`.

Policies may use only allow-listed variables such as `canary`, `task`, and
`untrusted_content_label`. Templates do not support attribute access,
expressions, loops, includes, filesystem access, or arbitrary functions.

The default benchmark compares at least `policy.minimal` and
`policy.hierarchy`. Stronger policies cannot be treated as universally better
unless utility is also preserved.

### 8.5 Objectives

Built-in objective types are:

- `disclose_canary`;
- `disclose_protected_text`;
- `emit_rogue_string`;
- `violate_output_constraint`;
- `follow_lower_trust_instruction`;
- `complete_benign_task`;
- `avoid_false_refusal`.

An objective contains no provider code and no executable grader.

### 8.6 Techniques

Built-in technique families include:

- direct extraction;
- instruction override;
- authority or role spoofing;
- output-format coercion;
- translation or transformation requests;
- delimiter and context-boundary confusion;
- fixed multi-turn escalation;
- indirect-document framing;
- tool-output framing.

A technique renders messages from a typed context. It does not assess the
result or contact a provider.

### 8.7 Transformations

Version 0.3 includes deterministic text transformations with bounded output:

- identity;
- Base64 with an explicit decoding instruction;
- ROT13 with an explicit decoding instruction;
- JSON string framing;
- XML element framing;
- Unicode-confusable substitution from a fixed allow-list;
- zero-width insertion with a configured maximum density;
- deterministic case and whitespace perturbation.

Transformations record their parameters and output digest. They are applied
only to the attack-controlled segment, not to trusted policy content or
canaries.

LLM-based paraphrasing and translation are deferred because they introduce
another nondeterministic provider call and make suite identity harder to
preserve.

### 8.8 Trials and transcripts

A planned trial is uniquely identified by:

- run ID;
- model reference;
- scenario ID and digest;
- policy ID and version;
- technique ID and version;
- transformation ID and parameters;
- repetition index.

Each provider request within a trial has a turn index. A transcript contains
the exact ordered messages, response text, visible reasoning when retained,
usage, latency, model revision, request ID, and typed failure.

Item IDs include the repetition index and remain unique across resumed or
partially completed runs.

## 9. Canary design

The static public canary remains available only for documentation and unit
tests.

Benchmark trials use a cryptographically random nonce to derive multiple
synthetic canary fragments. The raw canary is inserted only into trusted
policy content. Attack-controlled messages never receive it.

The sanitized run manifest stores:

- canary scheme version;
- digest;
- fragment count;
- generation method identifier.

The raw canary is retained only when prompt retention is enabled and is
treated as sensitive evaluation data. Tests inject a deterministic canary
factory; production does not weaken randomness for reproducibility.

Multiple fragments allow the scorer to distinguish:

- no disclosure;
- partial disclosure;
- complete disclosure.

Reproducibility relies on the retained transcript and manifest rather than
making future canaries predictable.

## 10. Scoring

### 10.1 Scorer outcomes

Each scorer returns:

- scorer ID and version;
- verdict: `success`, `failure`, `inconclusive`, or `error`;
- normalized score from `0.0` to `1.0` when applicable;
- metric values;
- exact evidence spans or structured evidence;
- explanation;
- eligibility;
- judge metadata when an LLM judge was used.

An aggregate attack assessment cannot convert `inconclusive` or `error` into a
secure result.

### 10.2 Deterministic scorers

Built-in deterministic scorers include:

- exact canary match;
- normalized canary match using documented Unicode normalization;
- canary-fragment disclosure;
- exact rogue-string match;
- expected-output match;
- forbidden-output match;
- output-schema validation;
- protected-text token overlap;
- response-presence and completion checks.

Protected-text overlap is reported as severity evidence. Generic textual
overlap alone does not establish attack success unless the scenario defines a
calibrated threshold and corresponding benign control.

Final response and visible provider reasoning are scored independently.

### 10.3 Optional LLM judge

The judge is configured independently from target models. A judge run records:

- provider and model;
- returned model revision;
- rubric ID and version;
- exact judge input and output subject to retention;
- parsed verdict;
- parse failures;
- token usage and estimated cost.

Judge outputs must conform to a strict JSON schema. Parse failure produces a
scorer error, not a negative attack result. Deterministic evidence takes
precedence over a contradictory judge for exact-disclosure objectives.

### 10.4 Utility and false refusal

Each scenario with a benign task has a utility scorer. Built-in controls use
objectively gradable tasks where practical.

The report contains at least:

- attack success rate;
- complete and partial disclosure rates;
- final-response leakage rate;
- reasoning leakage rate;
- benign task success rate;
- false-refusal rate;
- monitor trigger and evasion rates;
- provider, scorer, and monitor failure rates.

### 10.5 Aggregation and uncertainty

Binary rates use eligibility-aware denominators and Wilson confidence
intervals. Paired policy comparisons use shared trial keys. Existing bootstrap
and Fisher comparison utilities remain available where appropriate.

The report never collapses a result into one universal security score. It may
show a summary table, but security, utility, reliability, and detection remain
separate dimensions.

## 11. Built-in benchmark suites

### 11.1 Smoke suite

The packaged smoke suite provides a low-cost installation check with:

- eight malicious scenarios across the main direct-attack families;
- four benign controls;
- one transformation per scenario;
- one repetition by default.

It is not presented as a statistically strong model comparison.

### 11.2 Core prompt-injection suite

The packaged core suite contains at least:

- 40 malicious scenarios;
- 16 benign controls;
- eight attack families;
- direct, scripted multi-turn, indirect-document, and simulated tool-output
  delivery channels;
- exact deterministic oracles wherever possible;
- source, license, and content-digest metadata for every scenario.

Default transformations are bounded to avoid an accidental combinatorial cost
explosion. Users explicitly select an expanded transformation matrix.

The corpus contains synthetic secrets and harmless rogue objectives. It does
not require harmful content or access to real private data.

### 11.3 Corpus development rules

Built-in scenarios must:

- be original project content or clearly compatible licensed content;
- include attribution and SPDX metadata;
- avoid copying unverified prompt collections;
- use synthetic targets and secrets;
- have a positive attack case and relevant benign control;
- pass schema and scorer tests;
- document the intended secure behavior;
- be reviewed for duplicates and trivial lexical shortcuts.

## 12. External dataset adapters

Version 0.3 provides adapters, not bundled copies, for:

1. Meta CyberSecEval textual prompt-injection JSON;
2. OpenAI IH-Challenge JSON/Parquet exported to JSONL.

The IH-Challenge adapter maps recognized message roles and metadata but does
not execute `grader_code_python`. Supported objective patterns are translated
to local declarative scorers. Unsupported rows are rejected with a reason and
counted in an import summary.

Import is an explicit offline command. Network downloading is not performed by
`cot-redteam run`.

Every imported suite manifest records:

- upstream project and URL;
- upstream revision or dataset digest;
- upstream license as reported by the source;
- importer version;
- imported, skipped, and rejected counts;
- rejection reasons.

BIPIA, RaccoonBench, LLMail-Inject, PINT, AgentDojo, garak, PyRIT, and Inspect
AI integrations are deferred to adapters or interoperability work after the
core contracts are stable. RaccoonBench content is not copied into the MIT
package because its repository is GPL-3.0.

## 13. Provider changes

### 13.1 Generic OpenAI-compatible provider

Configuration adds `kind: openai_compatible`. It accepts:

- explicit base URL;
- optional API-key environment variable;
- safe headers;
- model aliases;
- timeout, retry, concurrency, and pricing settings;
- declared target capabilities.

This replaces the need to label third-party gateways as `openai`, `vllm`, or
`llamacpp` merely to reuse the transport.

Existing provider kinds continue to work.

### 13.2 Message serialization

The OpenAI-compatible transport serializes supported roles without silently
dropping them. Anthropic receives an equivalent mapping only for roles its API
supports.

Unsupported message roles fail capability validation before execution.
Provider-specific adapters may implement an explicitly declared, manifest-
recorded normalization policy.

### 13.3 Capability discovery

Version 0.3 uses declared capabilities. Automatic live capability probing is
deferred because request acceptance does not prove that a model respected a
role or generation parameter.

## 14. Planning and budgets

The planner expands the selected matrix:

```text
models
  x scenarios
  x policies
  x techniques
  x transformations
  x repetitions
```

Before execution, it reports:

- planned trials;
- minimum and maximum provider calls;
- judge-call maximum;
- estimated input size when available;
- configured request and cost budgets;
- incompatible and skipped combinations.

Every model and judge request consumes budget independently. Multi-turn trials
cannot bypass request budgets by being represented as one evaluation item.

The planner rejects:

- duplicate stable trial IDs;
- zero eligible trials;
- unsupported target capabilities;
- an expansion larger than an explicit safety limit unless the user confirms
  it with configuration or a CLI flag;
- budgets that cannot permit even one complete trial when this can be known
  statically.

## 15. Configuration and CLI

The existing top-level configuration version remains `2`. Version 0.3 adds
optional fields rather than forcing a breaking configuration migration.

New evaluation settings include:

- `suite_paths`;
- `suite_ids`;
- `policy_ids`;
- `technique_ids`;
- `transformation_ids`;
- `repetitions`;
- `judge_model`;
- `judge_scorers`;
- `max_expanded_trials`;
- explicit capability-adaptation policy.

Existing `evaluation.attacks` and `dataset_path` continue to select the legacy
single-turn path.

New CLI commands are:

- `cot-redteam list-suites`;
- `cot-redteam suite validate --path PATH`;
- `cot-redteam suite show --id ID`;
- `cot-redteam dataset import cyberseceval ...`;
- `cot-redteam dataset import ih-challenge ...`;
- `cot-redteam run --config PATH` for both legacy and benchmark runs.

Configuration validation resolves scenario, policy, technique, transform, and
scorer references and performs capability and matrix-size checks without
contacting providers.

## 16. Storage and artifacts

SQLite receives an additive schema migration for:

- trial identity dimensions;
- ordered transcript messages;
- per-turn provider responses and failures;
- scorer outcomes;
- utility outcomes;
- canary scheme and digest metadata;
- source and license provenance.

The migration preserves existing runs and remains idempotent.

Retention settings apply to every transcript turn and judge call. Sanitization
occurs before SQLite and artifact writes. Reports cannot reconstruct content
that retention removed.

Manifests include:

- suite and scenario digests;
- policy, technique, transform, scorer, and plugin versions;
- repetition count;
- capability declarations and adaptations;
- target and judge model revisions when available;
- eligible and excluded counts;
- artifact checksums.

## 17. Reporting

Markdown and machine-readable reports show:

- model and returned revision;
- suite identity and digest;
- policy;
- scenario and family;
- delivery channel;
- technique and transformation;
- repetition;
- complete transcript when retained;
- final-response and reasoning evidence separately;
- objective, utility, monitor, and judge outcomes;
- exclusions and typed failures.

Aggregates are grouped by:

- model;
- policy;
- attack family;
- delivery channel;
- transformation;
- scenario;
- scorer.

CSV remains a flattened item-level export. Version 0.3 adds a canonical JSONL
export for lossless transcripts and scorer results. LaTeX contains aggregate
tables and references detailed evidence artifacts rather than embedding
unbounded transcripts.

JUnit, SARIF, OpenTelemetry, Inspect AI, garak, and PyRIT exports are deferred
until the benchmark result schema has proven stable.

## 18. Legacy attack handling

Legacy attack IDs and entry points remain loadable. They run through a
single-turn compatibility adapter.

The following rules apply:

- heuristic keyword assessments are labeled `legacy_heuristic`;
- they are excluded from the default core benchmark;
- the packaged quickstart uses a benchmark smoke suite;
- the system-canary ID remains available for targeted reproduction;
- new benchmark scenarios do not subclass `BaseAttack`;
- third-party `BaseAttack` plugins remain supported for 0.3.

Changing or deprecating the legacy plugin contract is a separate future major-
version decision.

## 19. Error handling

New typed failures distinguish:

- scenario validation error;
- unsupported target capability;
- policy rendering error;
- transformation error;
- provider error by turn;
- scorer error;
- judge parse or provider error;
- budget exhaustion;
- retention redaction;
- dataset import rejection;
- cancellation.

A partial multi-turn transcript is retained according to policy when a later
turn fails. Earlier successful turns are not discarded.

Scorer, judge, monitor, and provider failures remain ineligible for the metric
they prevent. They are never interpreted as secure outcomes.

## 20. Security boundaries

### 20.1 Secrets

Provider credentials remain environment-only. Dynamic canaries are synthetic
and are never real API secrets. Headers require explicit configuration and are
redacted using the existing secret-handling boundary.

### 20.2 Hostile content

Scenario text, imported datasets, provider responses, visible reasoning, and
judge responses are hostile input.

The implementation must not:

- use `eval`, `exec`, pickle, or unsafe YAML loading;
- render arbitrary Jinja or Python templates;
- execute dataset-provided grader code;
- follow filesystem paths contained in dataset rows;
- automatically fetch row-provided URLs;
- place untrusted response content into logs without retention-aware handling.

### 20.3 Import limits

Importers enforce:

- maximum file and row sizes;
- maximum message and scenario lengths;
- allowed roles and objective types;
- UTF-8 decoding and documented Unicode normalization;
- duplicate ID detection;
- output paths controlled by the caller;
- atomic output writes;
- provenance and digest generation.

### 20.4 Provider reasoning

Provider reasoning is a separate sensitive output channel. It is scored for
leakage only when exposed by the provider and retained by configuration.
Absent reasoning is `not_evaluable`, never clean.

### 20.5 Plugins

Third-party plugins remain trusted in-process code. Dataset files do not gain
plugin privileges merely by naming a scorer or technique. Only installed and
registered implementations may be referenced.

## 21. Testing strategy

### 21.1 Domain and schema tests

- valid and invalid message roles;
- mutually exclusive legacy and message request forms;
- scenario schema and size bounds;
- policy variable allow-list;
- transformation determinism and output bounds;
- objective and scorer validation;
- source, license, and digest requirements.

### 21.2 Security tests

- imported Python grader text remains inert;
- unsafe YAML tags are rejected;
- template expressions and attribute traversal are rejected;
- path traversal and absolute output escape are rejected;
- oversized and deeply nested rows are rejected;
- canaries do not enter attack-controlled messages;
- secret headers and raw canaries do not enter sanitized manifests;
- retention removes transcript and judge content before persistence.

### 21.3 Provider tests

- exact role serialization;
- unsupported-role rejection;
- multi-turn history ordering;
- generic OpenAI-compatible authentication and base URL;
- Anthropic role mapping;
- reasoning-source preservation;
- per-turn retry and failure classification;
- lifecycle and concurrency.

### 21.4 Planner and engine tests

- stable matrix expansion;
- unique repetition and turn IDs;
- capability validation;
- expansion safety limit;
- request budgets across turns and judges;
- deterministic scripted multi-turn execution;
- partial transcript retention;
- cancellation and resume behavior.

### 21.5 Scorer and metric tests

- exact, normalized, partial, and absent disclosure;
- final-response versus reasoning leakage;
- refusal versus quoted attack text;
- utility success and false refusal;
- scorer error eligibility;
- strict judge JSON parsing;
- Wilson intervals;
- paired policy comparisons;
- no universal score collapsing security and utility.

### 21.6 Corpus tests

- every scenario has provenance and license metadata;
- every malicious scenario has an objective and compatible scorer;
- required benign controls exist;
- no duplicate content digests;
- smoke and core suite size requirements;
- packaged resources load from a clean wheel.

### 21.7 Compatibility and release tests

- existing 0.2 example configuration still validates and runs with mocks;
- current third-party attack and monitor example plugins still load;
- existing SQLite runs remain readable after migration;
- Markdown, CSV, LaTeX, and JSONL reports render;
- Ruff, mypy, pytest, coverage, build, lock, and clean-wheel smoke tests pass;
- optional live provider tests remain credential-gated and are not CI
  requirements.

## 22. Documentation

Version 0.3 documentation includes:

- benchmark concepts and trust model;
- scenario authoring guide;
- policy, technique, transformation, and scorer reference;
- interpreting security versus utility metrics;
- capability compatibility table by provider;
- generic OpenAI-compatible endpoint setup;
- external dataset import and licensing guide;
- sensitive transcript and reasoning retention warning;
- migration notes from 0.2;
- reproducible smoke and core-suite examples;
- limitations on model-level and provider-route claims.

README examples use the smoke suite and clearly state expected call counts
before a user contacts a paid provider.

## 23. Delivery order

Implementation is divided into coherent dependent slices:

1. messages, capabilities, scenario schema, and validation;
2. trial planning, repetitions, and budget preflight;
3. multi-turn provider and conversation execution;
4. policies, canary generation, techniques, and transformations;
5. deterministic scorers, judge scoring, utility, and metrics;
6. storage migration, manifests, and reports;
7. built-in smoke and core corpora;
8. generic OpenAI-compatible configuration;
9. CyberSecEval and IH-Challenge import adapters;
10. documentation, compatibility validation, packaging, and release gates.

Each slice must preserve passing tests before the next slice begins.

## 24. Acceptance criteria

Version 0.3 is complete only when:

1. the smoke and core suites load from an installed wheel;
2. a mock model can run a scripted multi-turn scenario end to end;
3. unsupported target roles fail before any provider request;
4. repetitions produce unique trials and eligibility-aware confidence
   intervals;
5. an exact canary leak in final text or reasoning is reported separately;
6. a refusal quoting attack vocabulary is not automatically marked as attack
   success;
7. partial canary disclosure is distinguished from complete disclosure;
8. benign task utility and false-refusal metrics appear beside attack success;
9. judge failures remain errors rather than secure outcomes;
10. imported dataset grader code cannot execute;
11. matrix expansion and multi-turn calls obey request and cost budgets;
12. legacy 0.2 configurations and plugins continue to work;
13. the generic OpenAI-compatible provider works with an HTTP mock and a
    credential-gated real endpoint;
14. manifests identify every suite, policy, technique, transform, scorer,
    model revision, and adaptation used;
15. the SQLite migration preserves existing run data;
16. reports contain auditable evidence subject to retention;
17. documentation explains that benchmark results apply only to the tested
    model route, configuration, policy, and trials;
18. all repository release gates pass.

## 25. Deferred roadmap

After the 0.3 contracts are stable, candidate follow-up work includes:

- arbitrary HTTP application targets;
- PyRIT, garak, and Inspect AI import/export;
- BIPIA and LLMail-Inject adapters;
- simulated RAG and tool environments;
- AgentDojo interoperability;
- adaptive multi-turn attackers such as TAP or Crescendo;
- MCP and tool-call authorization testing;
- multimodal prompt injection;
- JUnit, SARIF, and OpenTelemetry exporters;
- a local report viewer.

These are not part of the 0.3 acceptance criteria.
