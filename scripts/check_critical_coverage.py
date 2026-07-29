#!/usr/bin/env python3
"""Fail when critical modules are below 85% coverage."""

from __future__ import annotations

import json
import sys
from pathlib import Path

CRITICAL_PREFIXES = (
    "cot_redteam/core/config.py",
    "cot_redteam/core/types.py",
    "cot_redteam/eval/planner.py",
    "cot_redteam/eval/engine.py",
    "cot_redteam/eval/metrics.py",
    "cot_redteam/eval/budgets.py",
    "cot_redteam/storage/sqlite.py",
    "cot_redteam/storage/artifacts.py",
)

THRESHOLD = 85.0


def main(path: str) -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    files = data.get("files", {})
    failures: list[str] = []
    for prefix in CRITICAL_PREFIXES:
        matches = [k for k in files if k.endswith(prefix) or k.replace("\\", "/").endswith(prefix)]
        if not matches:
            # try loose match on module path fragment
            fragment = prefix.split("/")[-1]
            matches = [k for k in files if k.replace("\\", "/").endswith(fragment)]
        if not matches:
            failures.append(f"missing coverage data for {prefix}")
            continue
        key = matches[0]
        summary = files[key]["summary"]
        covered = summary.get("covered_lines", 0) + summary.get("covered_branches", 0)
        total = summary.get("num_statements", 0) + summary.get("num_branches", 0)
        # prefer percent_covered if present
        pct = summary.get("percent_covered")
        if pct is None:
            pct = (100.0 * covered / total) if total else 100.0
        if pct < THRESHOLD:
            failures.append(f"{key}: {pct:.1f}% < {THRESHOLD}%")
    if failures:
        print("Critical coverage failures:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print(f"All critical modules >= {THRESHOLD}%")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "coverage.json"))
