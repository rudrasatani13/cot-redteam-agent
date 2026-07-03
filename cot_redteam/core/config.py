"""
Configuration loader for CoT Red Teaming Agent.
Supports YAML config with environment variable substitution.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, Optional
import os
import yaml


class Config:
    """Global configuration singleton."""
    
    _instance: Optional[Config] = None
    _data: Dict[str, Any] = {}
    _config_path: Optional[Path] = None
    
    def __new__(cls) -> Config:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def load(self, config_path: str | Path = "config.yaml") -> Config:
        """Load configuration from YAML file."""
        self._config_path = Path(config_path).resolve()
        
        if not self._config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self._config_path}")
        
        with open(self._config_path, "r") as f:
            raw = yaml.safe_load(f)
        
        self._data = self._substitute_env_vars(raw)
        return self
    
    def _substitute_env_vars(self, obj: Any) -> Any:
        """Recursively substitute ${ENV_VAR} patterns."""
        if isinstance(obj, str):
            # Handle ${VAR} or ${VAR:-default} patterns
            import re
            def replace(match):
                var_expr = match.group(1)
                if ":-" in var_expr:
                    var, default = var_expr.split(":-", 1)
                    return os.getenv(var, default)
                return os.getenv(var_expr, match.group(0))
            return re.sub(r"\$\{([^}]+)\}", replace, obj)
        elif isinstance(obj, dict):
            return {k: self._substitute_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._substitute_env_vars(v) for v in obj]
        return obj
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get config value by dot-notation key (e.g., 'models.default')."""
        keys = key.split(".")
        val = self._data
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val
    
    def __getitem__(self, key: str) -> Any:
        return self.get(key)
    
    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None
    
    @property
    def data(self) -> Dict[str, Any]:
        return self._data.copy()
    
    @property
    def config_path(self) -> Optional[Path]:
        return self._config_path


# Global config instance
config = Config()