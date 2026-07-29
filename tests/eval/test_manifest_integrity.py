"""Manifest integrity: no stale self-checksum of manifest.json."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from cot_redteam.api import run_evaluation
from cot_redteam.core.config import load_config
from cot_redteam.core.types import GenerationRequest, ModelRef, ModelResponse, TokenUsage
from cot_redteam.providers.factory import ProviderFactory


class OkProvider:
    async def generate(self, model: ModelRef, request: GenerationRequest) -> ModelResponse:
        return ModelResponse(
            text="<think>ok</think>answer",
            model=model,
            usage=TokenUsage(1, 1),
            provider_request_id="r1",
        )

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_manifest_sha_matches_file_bytes(tmp_path: Path) -> None:
    dataset = tmp_path / "d.jsonl"
    dataset.write_text('{"id":"1","question":"2+2?"}\n', encoding="utf-8")
    cfg = {
        "version": 2,
        "global": {"seed": 1, "concurrency": 1},
        "providers": {"fake": {"kind": "vllm", "base_url": "http://localhost:9/v1"}},
        "evaluation": {
            "models": ["fake:local"],
            "attacks": ["injection.cot_injection"],
            "monitors": ["regex"],
            "dataset_path": str(dataset),
            "sample_count": 1,
        },
        "storage": {"path": str(tmp_path / "db.sqlite")},
        "artifacts": {"root": str(tmp_path / "artifacts")},
    }
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    config = load_config(cfg_path)

    class Factory(ProviderFactory):
        def __init__(self) -> None:
            self._config = config
            self._environ = {}
            self._transport_factory = None
            self._cache = {}
            self.provider = OkProvider()

        def create(self, model: ModelRef):
            return self.provider

        def resolve_model(self, value: str) -> ModelRef:
            return ModelRef.parse(value)

        async def aclose(self) -> None:
            await self.provider.aclose()

    run = await run_evaluation(config, provider_factory=Factory())
    root = Path(config.artifacts.root) / run.run_id
    manifest_path = root / "manifest.json"
    detached = root / "manifest.json.sha256"
    assert manifest_path.exists()
    assert detached.exists()

    body = manifest_path.read_bytes()
    actual = hashlib.sha256(body).hexdigest()
    recorded = detached.read_text(encoding="utf-8").split()[0]
    assert recorded == actual

    # Manifest artifact list must not claim a self-checksum of manifest.json.
    data = json.loads(body)
    paths = [a["path"] for a in data.get("artifacts", [])]
    assert not any(p.endswith("manifest.json") for p in paths)
