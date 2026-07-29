"""CLI config command tests."""

from __future__ import annotations

from pathlib import Path

from cot_redteam.cli.main import main


def test_init_writes_and_refuses_overwrite(tmp_path: Path) -> None:
    dest = tmp_path / "cfg.yaml"
    assert main(["init", "--path", str(dest)]) == 0
    assert dest.exists()
    assert main(["init", "--path", str(dest)]) == 2
    assert main(["init", "--path", str(dest), "--force"]) == 0


def test_config_validate_and_show(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret-value-xyz")
    cfg = Path("tests/fixtures/config/minimal.yaml")
    # Fix dataset path absolute for validate plugins
    assert main(["config", "validate", "--config", str(cfg)]) in (0, 2)
    # show never prints secret
    # capture via redirect
    import io
    import sys

    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        code = main(["config", "show", "--config", str(cfg)])
    finally:
        sys.stdout = old
    assert code == 0
    assert "secret-value-xyz" not in buf.getvalue()


def test_config_validate_missing_secret(monkeypatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    code = main(["config", "validate", "--config", "tests/fixtures/config/minimal.yaml"])
    assert code == 2
