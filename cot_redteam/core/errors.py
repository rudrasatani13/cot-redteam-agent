"""Public exception hierarchy and retry classification."""

from __future__ import annotations


class CotRedTeamError(Exception):
    """Base exception for the CoT Red Team Agent."""


class ConfigurationError(CotRedTeamError):
    """Invalid configuration, missing credentials, or bad overrides."""


class PluginError(CotRedTeamError):
    """Plugin registration, discovery, or construction failure."""


class ProviderError(CotRedTeamError):
    """Base class for provider transport failures."""


class TransientProviderError(ProviderError):
    """Retryable provider failure (timeouts, 429, 5xx, connection errors)."""


class PermanentProviderError(ProviderError):
    """Non-retryable provider failure (4xx except 429, schema-invalid payloads)."""


class BudgetExceededError(CotRedTeamError):
    """A configured run budget was exceeded."""


class UnknownPricingError(CotRedTeamError):
    """A cost ceiling is configured but a provider has unknown pricing."""


class DatasetError(CotRedTeamError):
    """Malformed or incomplete dataset input."""


class StorageError(CotRedTeamError):
    """Persistence or artifact store failure."""
