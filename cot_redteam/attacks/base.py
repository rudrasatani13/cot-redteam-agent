"""
Base interface for all attacks.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from cot_redteam.core.types import (
    AttackCategory, AttackResult, AttackSpec, ModelConfig, DatasetSample
)


class BaseAttack(ABC):
    """Base class for all CoT attacks."""
    
    # Override in subclasses
    name: str = "base_attack"
    category: AttackCategory = AttackCategory.INJECTION
    description: str = "Base attack class"
    version: str = "1.0.0"
    tags: List[str] = []
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.attack_config = self.config.get("attacks", {}).get("defaults", {})
    
    @abstractmethod
    def generate_prompt(self, sample: DatasetSample, **kwargs) -> str:
        """Generate the attack prompt for a given dataset sample."""
        pass
    
    @abstractmethod
    def evaluate_response(
        self, 
        response: str, 
        cot: Optional[str], 
        sample: DatasetSample,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Evaluate if the attack succeeded.
        Returns dict with at least: {'success': bool, 'metrics': {...}}
        """
        pass
    
    def extract_cot(self, response: str) -> Optional[str]:
        """Extract Chain of Thought from model response."""
        delimiters = self.attack_config.get("cot_delimiters", [
            "assistant", "####", "Step by step:", "<reasoning>", "</reasoning>"
        ])
        
        # Try to find CoT between delimiters
        for delim in delimiters:
            if delim in response:
                parts = response.split(delim)
                if len(parts) > 1:
                    # Return the part after the first delimiter
                    cot = parts[1].strip()
                    if cot:
                        return cot
        
        # Fallback: check if response starts with reasoning-like content
        lines = response.strip().split("\n")
        reasoning_lines = []
        for line in lines:
            line_lower = line.lower().strip()
            if any(kw in line_lower for kw in [
                "think", "reason", "step", "first", "then", "next", "finally",
                "therefore", "because", "since", "thus", "hence"
            ]):
                reasoning_lines.append(line)
            elif reasoning_lines:
                break
        
        if reasoning_lines:
            return "\n".join(reasoning_lines)
        
        return None
    
    def run(
        self, 
        model: "BaseModel", 
        sample: DatasetSample, 
        **kwargs
    ) -> AttackResult:
        """Run the attack on a model with a sample."""
        prompt = self.generate_prompt(sample, **kwargs)
        response = model.generate(prompt, **kwargs)
        cot = self.extract_cot(response) if self.attack_config.get("cot_extraction", True) else None
        eval_result = self.evaluate_response(response, cot, sample, **kwargs)
        
        return AttackResult(
            attack_id=f"{self.category.value}.{self.name}",
            attack_name=self.name,
            attack_category=self.category,
            model_config=model.config,
            prompt=prompt,
            response=response,
            cot=cot,
            success=eval_result.get("success", False),
            metrics=eval_result.get("metrics", {}),
            metadata=eval_result.get("metadata", {}),
        )
    
    def get_spec(self) -> AttackSpec:
        """Get attack specification for generative mutation."""
        return AttackSpec(
            name=self.name,
            category=self.category,
            description=self.description,
            prompt_template=self.get_prompt_template(),
            parameters=self.config,
            tags=self.tags,
        )
    
    def get_prompt_template(self) -> str:
        """Get the prompt template (override for generative attacks)."""
        return "{prompt}"
    
    def mutate(self, **kwargs) -> "BaseAttack":
        """Create a mutated version of this attack (for generative evolution)."""
        # Default: return self with modified config
        new_config = self.config.copy()
        new_config.update(kwargs)
        return self.__class__(new_config)


class AttackRegistry:
    """Registry for attack classes with auto-discovery."""
    
    _attacks: Dict[str, type[BaseAttack]] = {}
    _categories: Dict[AttackCategory, List[type[BaseAttack]]] = {}
    
    @classmethod
    def register(cls, attack_class: type[BaseAttack]) -> type[BaseAttack]:
        """Register an attack class."""
        key = f"{attack_class.category.value}.{attack_class.name}"
        cls._attacks[key] = attack_class
        
        if attack_class.category not in cls._categories:
            cls._categories[attack_class.category] = []
        cls._categories[attack_class.category].append(attack_class)
        return attack_class
    
    @classmethod
    def get(cls, key: str) -> Optional[type[BaseAttack]]:
        """Get attack class by key."""
        return cls._attacks.get(key)
    
    @classmethod
    def get_by_category(cls, category: AttackCategory) -> List[type[BaseAttack]]:
        """Get all attacks in a category."""
        return cls._categories.get(category, [])
    
    @classmethod
    def get_all(cls) -> Dict[str, type[BaseAttack]]:
        """Get all registered attacks."""
        return cls._attacks.copy()
    
    @classmethod
    def create(
        cls, 
        key: str, 
        config: Optional[Dict[str, Any]] = None
    ) -> Optional[BaseAttack]:
        """Create an attack instance."""
        attack_class = cls.get(key)
        if attack_class:
            return attack_class(config)
        return None
    
    @classmethod
    def list_names(cls) -> List[str]:
        """List all registered attack names."""
        return list(cls._attacks.keys())


def auto_discover_attacks(package: str = "cot_redteam.attacks") -> None:
    """Auto-discover and register all attacks in the package."""
    import importlib
    import pkgutil
    
    pkg = importlib.import_module(package)
    for _, module_name, _ in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
        try:
            importlib.import_module(module_name)
        except Exception as e:
            print(f"Warning: Failed to import {module_name}: {e}")
    
    # Also check subdirectories
    for _, submodule_name, is_pkg in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
        if is_pkg:
            auto_discover_attacks(submodule_name)