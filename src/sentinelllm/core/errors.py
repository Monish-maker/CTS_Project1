"""SentinelLLM-specific exceptions."""


class SentinelLLMError(Exception):
    """Base exception for SentinelLLM failures."""


class ConfigurationError(SentinelLLMError):
    """Raised when scan configuration is invalid."""


class FeatureNotImplementedError(SentinelLLMError):
    """Raised by an explicit Phase 1 boundary placeholder."""
