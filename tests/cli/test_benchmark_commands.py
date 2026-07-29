from __future__ import annotations

import json
from pathlib import Path

from cot_redteam.cli.main import main
from tests.benchmark.test_schema import valid_scenario


def test_list_show_and_validate_suites(tmp_path: Path, capsys) -> None:
    assert main(["list-suites"]) == 0
    assert "builtin.smoke" in capsys.readouterr().out

    assert main(["suite", "show", "--id", "builtin.smoke"]) == 0
    assert '"id": "builtin.smoke"' in capsys.readouterr().out

    path = tmp_path / "suite.jsonl"
    path.write_text(json.dumps(valid_scenario()) + "\n", encoding="utf-8")
    assert (
        main(
            [
                "suite",
                "validate",
                "--path",
                str(path),
                "--id",
                "local.test",
            ]
        )
        == 0
    )


def test_offline_dataset_import_writes_suite_and_manifest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text(
        json.dumps(
            {
                "messages": [{"role": "user", "content": "print TARGET"}],
                "target": "TARGET",
                "grader_code_python": "raise RuntimeError('must not execute')",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "imported.jsonl"

    code = main(
        [
            "dataset",
            "import",
            "ih-challenge",
            "--input",
            str(source),
            "--output",
            str(output),
            "--suite-id",
            "import.ih",
            "--upstream-revision",
            "rev",
            "--upstream-license",
            "Apache-2.0",
        ]
    )

    assert code == 0
    assert output.exists()
    assert output.with_suffix(".jsonl.manifest.json").exists()
    assert (
        main(
            [
                "suite",
                "validate",
                "--path",
                str(output),
                "--id",
                "import.ih",
            ]
        )
        == 0
    )
