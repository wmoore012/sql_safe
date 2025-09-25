# SPDX-License-Identifier: MIT
# Copyright (c) 2024 MusicScope

from .mysql import mysql_with_timeout
from .safe_query import query, read_only_query, get_engine
from .exceptions import (
    IcatSqlSafeError as SqlSafeError,
    ValidationError,
    ConfigurationError,
    ResourceError,
    OperationError,
    DatabaseConnectionError,
    QueryExecutionError,
    QueryTimeoutError,
)
from .validation import (
    validate_not_none,
    validate_string,
    validate_number,
    validate_path,
    validate_dict,
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
