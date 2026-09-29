class ReaiError(Exception):
    """Base class for concise user-facing errors."""


class ConfigError(ReaiError):
    """Raised when configuration cannot be loaded or validated."""


class InputValidationError(ReaiError):
    """Raised when an input path cannot be analyzed safely."""


class WorkspaceError(ReaiError):
    """Raised when a workspace cannot be created or reused safely."""


class IDAUnavailableError(ReaiError):
    """Raised when the configured IDA environment cannot be found."""


class IDAAnalysisError(ReaiError):
    """Raised when IDA analysis fails for a sample."""


class ExtractionError(ReaiError):
    """Raised when deterministic extraction cannot be completed."""


class AIProviderError(ReaiError):
    """Raised when an AI provider cannot complete a request."""


class EnrichmentError(ReaiError):
    """Raised when Phase 6 IDB enrichment cannot be completed safely."""


class ReportError(ReaiError):
    """Raised when Phase 7 report generation cannot be completed safely."""
