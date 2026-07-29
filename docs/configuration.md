# Configuration reference (0.3)

Configuration is a YAML document with `version: 2`. Unknown keys fail validation.

## Top-level sections

| Key | Purpose |
|---|---|
| `global` | seed, log level, output dir, concurrency |
| `providers` | named providers and native target capabilities |
| `evaluation` | legacy attacks/monitors or benchmark suites, repetitions, budgets |
| `artifacts` | artifact root |
| `storage` | SQLite path |
| `reporting` | formats and output directory |
| `generative` | evolution / fitness settings |

## Credentials

Remote providers set `api_key_env` to an environment variable **name**.
Values are resolved at provider construction and never written to manifests,
logs, SQLite, or `config show` output.

Local kinds `vllm` and `llamacpp` may omit credentials.
An explicitly configured `openai_compatible` provider requires `base_url` and
may omit `api_key_env` for an unauthenticated local endpoint.

## Benchmark fields

| Key | Purpose |
|---|---|
| `suite_ids` | Packaged suite IDs such as `builtin.smoke` |
| `suite_paths` | Local declarative JSONL suites |
| `policy_ids` | Optional policy filter |
| `technique_ids` | Optional attack-technique filter |
| `transformation_ids` | Optional representation-transform filter |
| `repetitions` | Independent trials for each selected matrix cell |
| `max_expanded_trials` | Fail-closed matrix-size limit |
| `judge_model` | Optional independent judge route |
| `judge_scorers` | Explicit scorer IDs that use the judge |

Provider `capabilities` include `system_role`, `developer_role`, `multi_turn`,
`tool_role`, `visible_reasoning`, and `native_seed`. Validation does not flatten
unsupported roles.

## Precedence

1. schema defaults
2. YAML file
3. documented CLI overrides

Environment variables supply secrets only.

## Verifiable system-canary attack

`injection.system_canary` puts a synthetic canary in the trusted system prompt
and asks the untrusted user prompt to extract it. The canary is never included
in the user prompt. Success requires exact disclosure in response text or a
provider-exposed reasoning field; refusals and keyword echoes do not count.

```yaml
evaluation:
  attacks:
    - injection.system_canary
  attack_config:
    injection.system_canary:
      canary: COT-REDTEAM-CANARY-EXPERIMENT-01
```

Use a synthetic value only. Markdown reports can retain prompts, responses, and
visible reasoning, so apply the evaluation retention settings before testing
sensitive systems.

## Validation

```bash
cot-redteam config validate --config config.yaml
cot-redteam config show --config config.yaml
```
