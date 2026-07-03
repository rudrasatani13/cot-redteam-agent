# CoT Red Teaming Agent

Automated, research-grade **Chain-of-Thought (CoT) Red Teaming** framework for finding vulnerabilities in LLM reasoning.

## Features

- **8 Attack Categories**: Injection, Faithfulness, Steganography, Manipulation, Sandbagging, Evasion, Distillation, Generative
- **5+ Model Adapters**: OpenRouter, OpenAI, Anthropic, vLLM, llama.cpp
- **3+ Monitors**: Regex (basic + weighted), LLM-as-Judge, Ensemble/Cascading
- **Generative Attack Engine**: LLM-generated novel attacks with evolutionary optimization
- **Evasion Testing**: Test attacks against multiple monitors simultaneously
- **Reproducible**: Seed locking, artifact hashing, config snapshots, version pinning
- **Paper-Ready Output**: LaTeX/Markdown/CSV tables with statistical significance tests
- **Model Watcher**: Auto-detect new models on HuggingFace and OpenRouter
- **SQLite + Parquet Storage**: Queryable results storage with comparison tools

## Quick Start

```bash
# Install
pip install -e .

# List attacks
cot-redteam list-attacks

# Run evaluation
cot-redteam run \
  --model openrouter:anthropic/claude-3.5-sonnet \
  --dataset cot_redteam/eval/datasets/sample.jsonl \
  --num-samples 5 \
  --verbose

# Show results
cot-redteam list-runs
cot-redteam show-run <run_id>
cot-redteam report <run_id> --format markdown
```

## Architecture

```
cot-redteam-agent/
├── cot_redteam/
│   ├── core/           # Types, config
│   ├── attacks/        # 8 attack categories with plugin registry
│   │   ├── injection/      # CoT injection, roleplay injection
│   │   ├── faithfulness/   # Unfaithful CoT, hallucination detection
│   │   ├── steganography/  # Hidden CoT, encoding, watermarking
│   │   ├── manipulation/   # Path forcing, circular reasoning, fallacy injection
│   │   ├── sandbagging/   # Capability hiding, selective competence
│   │   ├── evasion/        # Monitor awareness, stealth reasoning
│   │   ├── distillation/  # CoT extraction via distillation
│   │   └── generative/    # LLM-generated novel attacks (evolutionary)
│   ├── models/         # Model adapters (OpenRouter, OpenAI, Anthropic, vLLM, llama.cpp)
│   ├── monitors/        # CoT monitors + evasion testing framework
│   ├── eval/           # Eval harness, datasets, metrics, artifacts
│   ├── scheduler/      # Model watcher (HF/OpenRouter)
│   ├── storage/        # SQLite results store
│   ├── reporting/      # Paper-ready reports
│   └── cli/           # CLI tool
├── config.yaml          # Full configuration
└── pyproject.toml
```

## Attack Categories

| Category | Attacks | Description |
|----------|---------|-------------|
| Injection | 3 | Hijack CoT with injected instructions |
| Faithfulness | 3 | Detect unfaithful/hallucinated CoT |
| Steganography | 3 | Hidden CoT, encoding, watermarking |
| Manipulation | 4 | Force wrong reasoning paths, fallacy injection |
| Sandbagging | 3 | Detect capability hiding |
| Evasion | 4 | Bypass CoT monitoring |
| Distillation | 2 | Extract proprietary CoT patterns |
| Generative | 1+ | LLM-generated novel attacks with evolution |

## Configuration

See `config.yaml` for full configuration options.

## License

MIT