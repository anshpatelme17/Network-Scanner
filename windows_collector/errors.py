"""Collector-specific exceptions."""


class CollectorError(Exception):
    """Base class for collector failures."""


class ConfigError(CollectorError):
    """Configuration is missing or invalid."""


class SourceError(CollectorError):
    """The Windows event source could not be read."""


class SourceUnavailableError(SourceError):
    """PowerShell or the requested event channel is unavailable."""


class SourceDataError(SourceError):
    """The event source returned an unusable payload."""


class NormalizationError(CollectorError):
    """A raw Windows event cannot be mapped to the backend schema."""


class CheckpointError(CollectorError):
    """The checkpoint is unreadable or does not match the channel."""


class TransportError(CollectorError):
    """The backend HTTP request failed."""


class AuthenticationError(TransportError):
    """The backend rejected collector credentials."""


class BackendError(TransportError):
    """The backend returned a non-success response."""
