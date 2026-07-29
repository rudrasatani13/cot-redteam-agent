# Configuration reference (0.2)

Configuration is a YAML document with `version: 2`. Unknown keys fail validation.

## Top-level sections

| Key | Purpose |
|---|---|
| `global` | seed, log level, output dir, concurrency |
| `providers` | named providers (openrouter, openai, anthropic, vllm, llamacpp) |
| `evaluation` | models, attacks, monitors, dataset, budgets |
| `artifacts` | artifact root and retention flags |
| `storage` | SQLite path |
| `reporting` | formats and output directory |
| `generative` | evolution / fitness settings |

## Credentials

Remote providers set `api_key_env` to an environment variable **name**.
Values are resolved at provider construction and never written to manifests,
logs, SQLite, or `config show` output.

Local kinds `vllm` and `llamacpp` may omit credentials.

## Precedence

1. schema defaults  
2. YAML file  
3. documented CLI overrides  

Environment variables supply secrets only.

## Validation

```bash
cot-redteam config validate --config config.yaml
cot-redteam config show --config config.yaml
```
