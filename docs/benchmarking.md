# Prompt-Injection Benchmarking

Version 0.3 evaluates raw text model and chat-completion APIs. It does not
operate browsers, email, external tools, RAG systems, or production agents.

## Suites and trial matrix

`builtin.smoke` contains eight malicious scenarios and four benign controls.
It is a low-cost installation and integration check, not a statistically strong
comparison. `builtin.core` contains 40 malicious scenarios and 16 controls
across eight attack families and direct, multi-turn, indirect-document, and
simulated tool-output channels.

Each planned trial is one:

```text
model × scenario × policy × technique × transformation × repetition
```

The planner validates the expanded trial count, target role capabilities, and
minimum request budget before contacting a provider. Each conversation turn and
optional judge request consumes the shared request, token, elapsed-time, and
estimated-cost budgets.

## Configuration

```yaml
providers:
  gateway:
    kind: openai_compatible
    base_url: https://example.test/v1
    api_key_env: GATEWAY_API_KEY
    concurrency: 2
    capabilities:
      system_role: true
      developer_role: false
      multi_turn: true
      tool_role: false
      visible_reasoning: false
      native_seed: false

evaluation:
  models: [gateway:model-route]
  suite_ids: [builtin.smoke]
  repetitions: 3
  max_expanded_trials: 1000
  temperature: 0.0
  max_tokens: 512
  budgets:
    max_requests: 36
    max_estimated_cost: 1.00
```

The smoke and core suites include simulated tool-output cases. A provider with
`tool_role: false` is rejected before execution. Use a local filtered JSONL
suite when the target API cannot represent that role faithfully. The framework
does not silently flatten unsupported roles because that changes the experiment.

## Security and utility

Every malicious scenario defines an objective separately from its attack
technique and representation transform. Synthetic canaries are generated with
cryptographic randomness for each trial and inserted only into the trusted
policy. The manifest stores their digests and scheme metadata, not raw values.

Deterministic scorers cover:

- exact and Unicode-NFKC-normalized canary disclosure;
- partial canary-fragment disclosure;
- exact rogue, expected, and forbidden output;
- allow-listed JSON output shapes;
- protected-text token overlap;
- response presence and false refusal.

Final response and visible provider reasoning are scored independently. Absent
reasoning is not evaluable. Provider failures, scorer failures, and judge parse
failures are errors; they never become secure negative results. An optional
judge must return the strict configured JSON schema, and deterministic exact
evidence takes precedence for exact-disclosure objectives.

Reports keep security, utility, reliability, and monitor results separate.
Binary rates use eligible denominators and Wilson intervals. No universal
security score is produced.

## Reports and retention

Benchmark runs write:

- a lossless trial-level `benchmark.jsonl`;
- `manifest.json` plus a detached SHA-256 file;
- configured Markdown, CSV, and LaTeX reports;
- normalized SQLite rows for trials, messages, turns, scorers, and judges.

`evaluation.retain_prompts`, `retain_responses`, and `retain_reasoning` are
applied before every SQLite or artifact write. Scorer evidence and judge inputs
are redacted consistently with the channel they came from.

## External adapters

Imports are offline and never download data:

```bash
cot-redteam dataset import cyberseceval \
  --input upstream.jsonl \
  --output imported.jsonl \
  --suite-id import.cyberseceval \
  --upstream-revision REVISION \
  --upstream-license LICENSE

cot-redteam dataset import ih-challenge \
  --input upstream.jsonl \
  --output imported.jsonl \
  --suite-id import.ih \
  --upstream-revision REVISION \
  --upstream-license LICENSE
```

Only recognized declarative fields and deterministic target strings are
translated. An IH-Challenge-derived export must contain materialized `messages`
and a declarative `target`; raw training templates with an unresolved attack
placeholder are rejected because interpreting their arbitrary Python graders
would cross an execution boundary. Unsupported rows are rejected with counted
reasons. `grader_code_python` is recorded as ignored and is never executed.
Review the upstream license and generated manifest before distributing imported
content.
