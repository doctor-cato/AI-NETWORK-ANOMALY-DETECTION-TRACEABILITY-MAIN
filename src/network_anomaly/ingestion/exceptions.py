"""Exceptions for multi-source ingestion and compatibility evaluation."""

from __future__ import annotations


class IngestionError(Exception):
    """Base exception for all ingestion and parsing errors."""


class SourceUnsupportedError(IngestionError):
    """Raised when an unregistered or explicitly unsupported source is ingested."""


class FormatInvalidError(IngestionError):
    """Raised when the physical format cannot be parsed (malformed CSV, invalid JSON)."""


class SchemaValidationError(IngestionError):
    """Raised when the input record or file violates required schema constraints."""


class FeatureIncompatibleError(IngestionError):
    """Raised when required ML baseline features are missing or cannot be derived."""


class SemanticMismatchError(IngestionError):
    """Raised when a feature has semantic incompatibility (e.g. sFlow sampled counters)."""


class AbstentionError(IngestionError):
    """Raised when the system fail-closed abstains from ML inference."""


class OODWarningException(IngestionError):
    """Raised or flagged when out-of-distribution values or shortcut collapse are detected."""
