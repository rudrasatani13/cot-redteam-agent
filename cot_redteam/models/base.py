"""
Base interface for model adapters.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, AsyncGenerator
from cot_redteam.core.types import ModelConfig


class BaseModel(ABC):
    """Base class for all model adapters."""
    
    def __init__(self, config: ModelConfig):
        self.config = config
        self._client = None
    
    @abstractmethod
    def generate(
        self, 
        prompt: str, 
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> str:
        """Generate a response from the model."""
        pass
    
    @abstractmethod
    async def agenerate(
        self, 
        prompt: str, 
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> str:
        """Async generate a response."""
        pass
    
    @abstractmethod
    def stream(
        self, 
        prompt: str, 
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """Stream response tokens."""
        pass
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information for logging/reproducibility."""
        return {
            "provider": self.config.provider.value,
            "model_id": self.config.model_id,
            "full_id": self.config.full_id,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }


class ModelRegistry:
    """Registry for model adapters."""
    
    _adapters: Dict[str, type[BaseModel]] = {}
    
    @classmethod
    def register(cls, provider: str):
        """Decorator to register a model adapter."""
        def wrapper(adapter_class: type[BaseModel]) -> type[BaseModel]:
            cls._adapters[provider] = adapter_class
            return adapter_class
        return wrapper
    
    @classmethod
    def get(cls, provider: str) -> Optional[type[BaseModel]]:
        """Get adapter class by provider name."""
        return cls._adapters.get(provider)
    
    @classmethod
    def create(cls, config: ModelConfig) -> BaseModel:
        """Create a model instance from config."""
        adapter_class = cls.get(config.provider.value)
        if not adapter_class:
            raise ValueError(f"No adapter registered for provider: {config.provider.value}")
        return adapter_class(config)
    
    @classmethod
    def list_providers(cls) -> List[str]:
        """List all registered providers."""
        return list(cls._adapters.keys())


def auto_discover_models(package: str = "cot_redteam.models") -> None:
    """Auto-discover and register all model adapters."""
    import importlib
    import pkgutil
    
    pkg = importlib.import_module(package)
    for _, module_name, _ in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
        try:
            importlib.import_module(module_name)
        except Exception as e:
            print(f"Warning: Failed to import {module_name}: {e}")