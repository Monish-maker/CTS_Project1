"""SentinelLLM-specific exceptions."""


class SentinelLLMError(Exception):
    """Base exception for SentinelLLM failures."""


class ConfigurationError(SentinelLLMError):
    """Raised when scan configuration is invalid."""


class FeatureNotImplementedError(SentinelLLMError):
    """Raised when an optional extension has no configured implementation."""
