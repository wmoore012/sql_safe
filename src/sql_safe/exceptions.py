# SPDX - License - Identifier: MIT
# Copyright (c) 2025 Perday CatalogLAB™

"""
Custom exceptions for icat - sql - safe module.

This module provides comprehensive error handling with specific exception types
for different failure scenarios, enabling precise error handling and debugging.
"""

from __future__ import annotations

from typing import Any


class IcatSqlSafeError(Exception):
    """Base exception for all icat - sql - safe errors."""

    def __init__(
        self, message: str, details: dict[str, Any] | None = None, suggestion: str | None = None
    ) -> None:
        """
        Initialize the exception with detailed error information.

        Args:
            message: Human - readable error message
            details: Additional error context and debugging information
            suggestion: Suggested solution or next steps
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.suggestion = suggestion

    def __str__(self) -> str:
        """Return formatted error message with details and suggestions."""
        result = self.message

        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            result += f" (Details: {details_str})"

        if self.suggestion:
            result += f" Suggestion: {self.suggestion}"

        return result


class ValidationError(IcatSqlSafeError):
    """Raised when input validation fails."""

    def __init__(
        self, field: str, value: Any, expected: str, suggestion: str | None = None
    ) -> None:
        """
        Initialize validation error with field - specific information.

        Args:
            field: Name of the field that failed validation
            value: The invalid value that was provided
            expected: Description of what was expected
            suggestion: How to fix the validation error
        """
        message = f"Invalid {field}: got {type(value).__name__} '{value}', expected {expected}"
        details = {"field": field, "value": value, "expected": expected}
        super().__init__(message, details, suggestion)
        self.field = field
        self.value = value
        self.expected = expected


class ConfigurationError(IcatSqlSafeError):
    """Raised when configuration is invalid or missing."""

    def __init__(self, config_key: str, issue: str, suggestion: str | None = None) -> None:
        """
        Initialize configuration error.

        Args:
            config_key: The configuration key that has an issue
            issue: Description of the configuration problem
            suggestion: How to fix the configuration
        """
        message = f"Configuration error for '{config_key}': {issue}"
        details = {"config_key": config_key, "issue": issue}
        super().__init__(message, details, suggestion)
        self.config_key = config_key
        self.issue = issue


class ResourceError(IcatSqlSafeError):
    """Raised when system resources are unavailable or exhausted."""

    def __init__(
        self,
        resource: str,
        issue: str,
        current_usage: str | None = None,
        suggestion: str | None = None,
    ) -> None:
        """
        Initialize resource error.

        Args:
            resource: The resource that is unavailable (memory, disk, network, etc.)
            issue: Description of the resource problem
            current_usage: Current resource usage information
            suggestion: How to resolve the resource issue
        """
        message = f"Resource error ({resource}): {issue}"
        details = {"resource": resource, "issue": issue}
        if current_usage:
            details["current_usage"] = current_usage
        super().__init__(message, details, suggestion)
        self.resource = resource
        self.issue = issue
        self.current_usage = current_usage


class OperationError(IcatSqlSafeError):
    """Raised when an operation fails due to business logic or external factors."""

    def __init__(
        self,
        operation: str,
        reason: str,
        retry_possible: bool = False,
        suggestion: str | None = None,
    ) -> None:
        """
        Initialize operation error.

        Args:
            operation: The operation that failed
            reason: Why the operation failed
            retry_possible: Whether retrying the operation might succeed
            suggestion: How to resolve the operation failure
        """
        message = f"Operation '{operation}' failed: {reason}"
        details = {"operation": operation, "reason": reason, "retry_possible": retry_possible}
        super().__init__(message, details, suggestion)
        self.operation = operation
        self.reason = reason
        self.retry_possible = retry_possible


class DatabaseConnectionError(ResourceError):
    """Raised when database connection fails."""

    def __init__(
        self, database_url: str, original_error: str | None = None, suggestion: str | None = None
    ) -> None:
        issue = (
            f"Failed to connect to database: {original_error}"
            if original_error
            else "Connection failed"
        )
        super().__init__(
            "database_connection",
            issue,
            suggestion=suggestion or "Check database URL, credentials, and network connectivity",
        )
        self.database_url = database_url
        self.original_error = original_error


class QueryExecutionError(OperationError):
    """Raised when SQL query execution fails."""

    def __init__(self, query: str, error_message: str, suggestion: str | None = None) -> None:
        super().__init__(
            "query_execution",
            f"Query failed: {error_message}",
            suggestion=suggestion or "Check query syntax and database permissions",
        )
        self.query = query
        self.error_message = error_message


class QueryTimeoutError(TimeoutError):
    """Raised when SQL query times out."""

    def __init__(self, query: str, timeout_ms: int, suggestion: str | None = None) -> None:
        super().__init__(
            timeout_ms / 1000,
            "query_execution",
            suggestion or "Try optimizing the query or increasing timeout_ms",
        )
        self.query = query
        self.timeout_ms = timeout_ms
