"""
Model watcher — detect new models on HuggingFace and OpenRouter.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field
import json
import httpx
import asyncio


@dataclass
class ModelInfo:
    """Information about a discovered model."""
    model_id: str
    provider: str  # "huggingface" or "openrouter"
    name: str
    created_at: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    downloads: int = 0
    likes: int = 0
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "provider": self.provider,
            "name": self.name,
            "created_at": self.created_at,
            "tags": self.tags,
            "downloads": self.downloads,
            "likes": self.likes,
            "description": self.description[:500],
            "metadata": self.metadata,
        }


class ModelWatcher:
    """
    Watch HuggingFace and OpenRouter for new models.
    Supports filtering by tags, tracking seen models, and notifications.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.seen_models: set[str] = set()
        self.state_file = self.config.get("state_file", ".model_watcher_state.json")
        self._load_state()
    
    def _load_state(self) -> None:
        """Load seen models from state file."""
        from pathlib import Path
        path = Path(self.state_file)
        if path.exists():
            with open(path, "r") as f:
                data = json.load(f)
                self.seen_models = set(data.get("seen_models", []))
    
    def _save_state(self) -> None:
        """Save seen models to state file."""
        with open(self.state_file, "w") as f:
            json.dump({"seen_models": list(self.seen_models)}, f, indent=2)
    
    async def check_huggingface(
        self,
        tags: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[ModelInfo]:
        """Check HuggingFace for new models."""
        tag_filter = tags or ["text-generation", "llm", "causal-lm", "instruct"]
        models = []
        
        async with httpx.AsyncClient(timeout=30) as client:
            for tag in tag_filter:
                try:
                    resp = await client.get(
                        "https://huggingface.co/api/models",
                        params={"tags": tag, "sort": "createdAt", "direction": -1, "limit": limit}
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    
                    for item in data:
                        model_id = item.get("modelId", item.get("id", ""))
                        if not model_id:
                            continue
                        
                        models.append(ModelInfo(
                            model_id=model_id,
                            provider="huggingface",
                            name=model_id.split("/")[-1],
                            created_at=item.get("createdAt"),
                            tags=item.get("tags", []),
                            downloads=item.get("downloads", 0),
                            likes=item.get("likes", 0),
                            description=item.get("description", ""),
                            metadata={
                                "pipeline_tag": item.get("pipeline_tag"),
                                "library_name": item.get("library_name"),
                            }
                        ))
                except Exception as e:
                    print(f"Error fetching HF models for tag '{tag}': {e}")
        
        return models
    
    async def check_openrouter(self) -> List[ModelInfo]:
        """Check OpenRouter for available models."""
        models = []
        
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.get("https://openrouter.ai/api/v1/models")
                resp.raise_for_status()
                data = resp.json()
                
                for item in data.get("data", []):
                    model_id = item.get("id", "")
                    if not model_id:
                        continue
                    
                    models.append(ModelInfo(
                        model_id=model_id,
                        provider="openrouter",
                        name=model_id.split("/")[-1],
                        created_at=str(item.get("created", "")),
                        tags=[],
                        downloads=int(item.get("context_length", 0)),
                        metadata={
                            "context_length": item.get("context_length"),
                            "pricing": item.get("pricing"),
                            "architecture": item.get("architecture"),
                        }
                    ))
            except Exception as e:
                print(f"Error fetching OpenRouter models: {e}")
        
        return models
    
    async def check_all(self) -> Dict[str, List[ModelInfo]]:
        """Check all sources for models."""
        hf_models, or_models = await asyncio.gather(
            self.check_huggingface(),
            self.check_openrouter(),
            return_exceptions=True
        )
        
        # Handle exceptions from gather
        if isinstance(hf_models, Exception):
            hf_models = []
        if isinstance(or_models, Exception):
            or_models = []
        
        return {"huggingface": hf_models, "openrouter": or_models}
    
    def get_new_models(self, all_models: Dict[str, List[ModelInfo]]) -> Dict[str, List[ModelInfo]]:
        """Filter to models not seen before."""
        new_models: Dict[str, List[ModelInfo]] = {"huggingface": [], "openrouter": []}
        
        for provider, models in all_models.items():
            for model in models:
                model_key = f"{provider}:{model.model_id}"
                if model_key not in self.seen_models:
                    new_models[provider].append(model)
                    self.seen_models.add(model_key)
        
        self._save_state()
        return new_models
    
    async def watch(
        self,
        callback: Optional[Callable[[List[ModelInfo]], None]] = None,
        interval_hours: float = 6
    ) -> None:
        """Watch for new models periodically."""
        interval_seconds = int(interval_hours * 3600)
        
        while True:
            print(f"[{datetime.now().isoformat()}] Checking for new models...")
            
            all_models = await self.check_all()
            new_models = self.get_new_models(all_models)
            
            total_new = sum(len(v) for v in new_models.values())
            
            if total_new > 0:
                print(f"  Found {total_new} new models!")
                for provider, models in new_models.items():
                    for m in models[:5]:
                        print(f"    [{provider}] {m.model_id}")
                
                if callback:
                    all_new = new_models["huggingface"] + new_models["openrouter"]
                    callback(all_new)
            else:
                print("  No new models.")
            
            await asyncio.sleep(interval_seconds)