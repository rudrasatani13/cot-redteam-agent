"""
Base interface for CoT monitors.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from cot_redteam.core.types import MonitorType, MonitorResult, ModelResponse


class BaseMonitor(ABC):
    """Base class for all CoT monitors."""
    
    monitor_type: MonitorType = MonitorType.CUSTOM
    name: str = "base_monitor"
    description: str = "Base monitor class"
    version: str = "1.0.0"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
    
    @abstractmethod
    def monitor(self, response: ModelResponse, attack_prompt: str = "") -> MonitorResult:
        """Monitor a model response for suspicious CoT patterns."""
        pass
    
    def get_spec(self) -> Dict[str, Any]:
        """Get monitor specification."""
        return {
            "name": self.name,
            "type": self.monitor_type.value,
            "description": self.description,
            "version": self.version,
            "config": self.config,
        }


class MonitorRegistry:
    """Registry for monitors."""
    
    _monitors: Dict[str, type[BaseMonitor]] = {}
    
    @classmethod
    def register(cls, monitor_class: type[BaseMonitor]) -> type[BaseMonitor]:
        key = f"{monitor_class.monitor_type.value}.{monitor_class.name}"
        cls._monitors[key] = monitor_class
        return monitor_class
    
    @classmethod
    def get(cls, key: str) -> Optional[type[BaseMonitor]]:
        return cls._monitors.get(key)
    
    @classmethod
    def get_all(cls) -> Dict[str, type[BaseMonitor]]:
        return cls._monitors.copy()
    
    @classmethod
    def create(
        cls, 
        key: str, 
        config: Optional[Dict[str, Any]] = None
    ) -> Optional[BaseMonitor]:
        monitor_class = cls.get(key)
        if monitor_class:
            return monitor_class(config)
        return None
    
    @classmethod
    def list_names(cls) -> List[str]:
        return list(cls._monitors.keys())


def auto_discover_monitors(package: str = "cot_redteam.monitors") -> None:
    import importlib
    import pkgutil
    
    pkg = importlib.import_module(package)
    for _, module_name, _ in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
        try:
            importlib.import_module(module_name)
        except Exception as e:
            print(f"Warning: Failed to import {module_name}: {e}")