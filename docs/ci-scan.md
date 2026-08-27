# Consumer CI scan with GitHub Actions

This repository's own [nightly scan](../.github/workflows/nightly-scan.yml) is
an offline tripwire for *this* codebase. Downstream users who install
`cot-redteam-agent` from PyPI need a copy-paste job for *their* repos.

`cot-redteam scan` is CI-friendly:

| Exit | Meaning | Typical CI treatment |
|---|---|---|
| `0` | Clean — no findings | Pass |
| `1` | Findings (compliant disclosure) | Fail the gate; this is not a flake |
| `2` | Config or environment error | Fail; fix YAML / secrets / install |
| `3` | Partial / inconclusive (errors, budget) | Fail; do not treat as clean |

Gate on `1` when you want findings to break the build. Do not retry `1` as if
the runner were flaky.

The mock provider is a pipeline smoke test, **not** a model-security score.
A green mock job only proves the CLI, config, and exit-code path work.

## Keyless mock job (stays green)

`mock_mode: refuse` holds the synthetic canary, so `scan` should exit `0`.
Packaged equivalent: `cot_redteam/data/mock_refuse.example.yaml`. From a clone
you can also write the auto demo with `cot-redteam init --path scan.yaml --demo mock`
and then switch `mock_mode` to `refuse` if the job must stay green (`auto` /
`disclose` exit `1` by design).

```yaml
name: cot-redteam-scan

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  mock-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install cot-redteam-agent
        run: |
          python -m pip install -U pip
          python -m pip install "cot-redteam-agent==0.6.0"
      - name: Keyless compliance scan (mock refuse) + SARIF
        run: |
          cat > scan.yaml <<'YAML'
          version: 2
          global:
            seed: 1
            output_dir: ./results-scan
            concurrency: 1
          providers:
            mock:
              kind: mock
              mock_mode: refuse
          evaluation:
            models:
              - mock:target
            dataset_path: pkg:sample.jsonl
            sample_count: 1
            budgets:
              max_requests: 40
              max_elapsed_seconds: 300
            retain_prompts: false
            retain_responses: false
          storage:
            path: ./results-scan/cot_redteam.db
          YAML
          cot-redteam config validate --config scan.yaml
          cot-redteam scan --config scan.yaml --sarif scan.sarif.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: cot-redteam-sarif
          path: scan.sarif.json
```

No API keys appear in the YAML. The `mock` provider never reads one.

To pin whatever is current on PyPI instead of `0.6.0`, use
`python -m pip install cot-redteam-agent` (still no secrets).

## Real target (needs secrets, never YAML)

Point `evaluation.models` at a hosted or local route and set the matching
provider kind. Put credentials in GitHub Actions secrets and map them to the
environment variable names the config already declares (`api_key_env`), for
example:

```yaml
      - name: Scan a real provider route
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        run: cot-redteam scan --config config.yaml --sarif scan.sarif.json
```

Never commit `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or
any other provider secret in workflow YAML, config files, or fixtures.

A real-target job that exits `1` means the scan found a compliant disclosure
on that route — treat it as a finding, not a flake. Exit `3` means the run
was incomplete; do not report that as a clean pass.

Optional: upload `scan.sarif.json` to GitHub code scanning with
`github/codeql-action/upload-sarif` if your repository enables that
permission. SARIF schema is unchanged by this snippet; see `scan --sarif` and
`report --format sarif`.

## Related docs

- [Try it in 30 seconds (README)](../README.md#try-it-in-30-seconds-no-api-key)
- [Comparisons](comparisons.md)
- [Configuration](configuration.md)
- [Providers](providers.md)
