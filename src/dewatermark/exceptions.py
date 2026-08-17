"""Stable exception hierarchy for callers and automation."""


class DewatermarkError(Exception):
    """Base class for package errors."""


class ConfigurationError(DewatermarkError, ValueError):
    """Configuration is invalid or incomplete."""


class BackendUnavailableError(DewatermarkError, RuntimeError):
    """A requested processing backend cannot run."""


class RemoteProcessingDeniedError(DewatermarkError, PermissionError):
    """Text transmission was denied by the active privacy policy."""


class QualityRejectedError(DewatermarkError):
    """A candidate failed configured quality requirements."""


class AdapterError(DewatermarkError):
    """An external extension failed its contract."""
