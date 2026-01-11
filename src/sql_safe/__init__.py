# SPDX - License - Identifier: MIT
# Copyright (c) 2025 Perday CatalogLAB™

from .exceptions import (
    ConfigurationError,
    DatabaseConnectionError,
    OperationError,
    QueryExecutionError,
    QueryTimeoutError,
    ResourceError,
    ValidationError,
)
from .exceptions import (
    IcatSqlSafeError as SqlSafeError,
)
from .mysql import mysql_with_timeout
from .safe_query import get_engine, query, read_only_query
from .validation import (
    validate_dict,
    validate_not_none,
    validate_number,
    validate_path,
    validate_string,
)

__all__ = [
    "mysql_with_timeout",
    "query",
    "read_only_query",
    "get_engine",
    # Exceptions
    "SqlSafeError",
    "ValidationError",
    "ConfigurationError",
    "ResourceError",
    "OperationError",
    "DatabaseConnectionError",
    "QueryExecutionError",
    "QueryTimeoutError",
    # Validation
    "validate_not_none",
    "validate_string",
    "validate_number",
    "validate_path",
    "validate_dict",
]
