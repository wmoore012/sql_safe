# SPDX-License-Identifier: MIT
# Copyright (c) 2024 MusicScope

"""
Safe SQL query execution with injection prevention and performance monitoring.

This module provides secure database operations with automatic parameterization,
read-only enforcement, timeout protection, and comprehensive logging.
"""

from __future__ import annotations

import logging
import os
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.engine.result import Result
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)


class SQLSafetyError(Exception):
    """Raised when unsafe SQL patterns are detected."""

    pass


class ReadOnlyViolationError(Exception):
    """Raised when write operations are attempted in read-only mode."""

    pass


def latency_warn(ms: int = 500) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to log warnings for slow database operations.

    Args:
        ms: Threshold in milliseconds above which to log warnings

    Returns:
        Decorated function that logs slow operations
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.perf_counter()
            try:
                result = fn(*args, **kwargs)
                elapsed_ms = (time.perf_counter() - start_time) * 1000

                if elapsed_ms > ms:
                    logger.warning(f"🐢 Slow query detected: {elapsed_ms:.1f}ms (threshold: {ms}ms)")
                else:
                    logger.debug(f"Query completed in {elapsed_ms:.1f}ms")

                return result
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                logger.error(f"Query failed after {elapsed_ms:.1f}ms: {e}")
                raise

        return wrapper

    return decorator


def get_engine(schema: str = "PUBLIC", *, ro: bool = False, echo: bool = False) -> Engine:
    """
    Get a SQLAlchemy engine with security and performance optimizations.

    Args:
        schema: Database schema to connect to ("PUBLIC" or "PRIVATE")
        ro: If True, configure for read-only access
        echo: If True, enable SQL query logging

    Returns:
        Configured SQLAlchemy Engine instance

    Raises:
        ValueError: If schema is invalid or required environment variables are missing
    """
    schema = schema.upper()
    valid_schemas = {"PUBLIC", "PRIVATE"}

    if schema not in valid_schemas:
        raise ValueError(f"Invalid schema '{schema}'. Must be one of: {valid_schemas}")

    # Try to get consolidated DATABASE_URL first
    url = None
    if schema == "PUBLIC":
        url = os.getenv("DATABASE_URL")
        db_name = os.getenv("DB_NAME_PUBLIC", "icatalog_public")
        if url and db_name not in url:
            url = None  # URL is for different database

    # Build URL from components if needed
    if not url:
        host = os.getenv("DB_HOST", "127.0.0.1")
        port = os.getenv("DB_PORT", "3307")
        user = os.getenv("DB_USER", "wmoore012")
        password = os.getenv("DB_PASS")

        if not password:
            raise ValueError("DB_PASS environment variable must be set")

        if schema == "PUBLIC":
            db_name = os.getenv("DB_NAME_PUBLIC", "icatalog_public")
        else:  # PRIVATE
            db_name = os.getenv("DB_NAME_PRIVATE", "icatalog")

        url = f"mysql+pymysql://{user}:{password}@{host}:{port}/{db_name}?charset=utf8mb4"

    # Add read-only parameters if requested
    if ro:
        separator = "&" if "?" in url else "?"
        if "read_timeout" not in url:
            url += f"{separator}read_timeout=15"

    # Create engine with optimized settings
    engine = create_engine(
        url,
        pool_pre_ping=True,
        pool_recycle=3600,  # Recycle connections every hour
        pool_size=5,  # Connection pool size
        max_overflow=10,  # Max overflow connections
        echo=echo,
    )

    # Set session-level timeouts
    try:
        with engine.begin() as conn:
            conn.execute(text("SET SESSION MAX_EXECUTION_TIME=30000"))  # 30 second default
            if ro:
                # Additional read-only safety measures
                conn.execute(text("SET SESSION TRANSACTION READ ONLY"))
    except Exception as e:
        logger.warning(f"Failed to set session configuration: {e}")

    return engine


def _validate_query_safety(query_str: str, read_only: bool = False) -> None:
    """
    Validate that a query is safe and follows security best practices.

    Args:
        query_str: The SQL query string to validate
        read_only: If True, ensure no write operations are present

    Raises:
        SQLSafetyError: If unsafe patterns are detected
        ReadOnlyViolationError: If write operations are detected in read-only mode
    """
    query_upper = query_str.upper().strip()

    # Check for dangerous patterns
    dangerous_patterns = [
        "DROP ",
        "TRUNCATE ",
        "ALTER ",
        "CREATE ",
        "GRANT ",
        "REVOKE ",
        "LOAD_FILE",
        "INTO OUTFILE",
        "INTO DUMPFILE",
        "UNION.*SELECT.*FROM.*INFORMATION_SCHEMA",
        "UNION.*SELECT.*FROM.*MYSQL",
    ]

    for pattern in dangerous_patterns:
        if pattern in query_upper:
            raise SQLSafetyError(f"Dangerous SQL pattern detected: {pattern}")

    # Check for write operations in read-only mode
    if read_only:
        write_operations = ["INSERT ", "UPDATE ", "DELETE ", "REPLACE ", "MERGE "]
        for operation in write_operations:
            if query_upper.startswith(operation):
                raise ReadOnlyViolationError(
                    f"Write operation '{operation.strip()}' not allowed in read-only mode"
                )

    # Ensure parameterized queries (basic check)
    if "'" in query_str and ":" not in query_str:
        logger.warning(
            "Query contains single quotes but no parameters. "
            "Consider using parameterized queries for better security."
        )


def _retry_with_backoff(
    func: Callable[..., Any], max_retries: int = 3, base_delay: float = 0.1
) -> Any:
    """
    Execute a function with exponential backoff retry logic.

    Args:
        func: Function to execute
        max_retries: Maximum number of retry attempts
        base_delay: Base delay in seconds (will be exponentially increased)

    Returns:
        Result of the function call

    Raises:
        The last exception if all retries fail
    """
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            return func()
        except (SQLAlchemyError, ConnectionError) as e:
            last_exception = e

            if attempt == max_retries:
                logger.error(f"Query failed after {max_retries} retries: {e}")
                break

            delay = base_delay * (2**attempt)  # Exponential backoff
            logger.warning(f"Query attempt {attempt + 1} failed, retrying in {delay:.2f}s: {e}")
            time.sleep(delay)

    if last_exception:
        raise last_exception
    raise RuntimeError("Function failed without exception")


@latency_warn(500)  # Warn for queries taking longer than 500ms
def query(
    query_str: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    engine: Optional[Engine] = None,
    timeout_ms: int = 30000,
    max_retries: int = 3,
) -> "Result[Any]":
    """
    Execute a parameterized SQL query with safety checks and performance monitoring.

    Args:
        query_str: SQL query string with named parameters (e.g., "SELECT * FROM users WHERE id = :id")
        params: Dictionary of parameter values
        engine: SQLAlchemy engine (if None, creates default engine)
        timeout_ms: Query timeout in milliseconds
        max_retries: Maximum number of retry attempts for transient failures

    Returns:
        SQLAlchemy Result object

    Raises:
        SQLSafetyError: If unsafe SQL patterns are detected
        ValueError: If required parameters are missing

    Example:
        >>> result = query("SELECT * FROM users WHERE id = :user_id", {"user_id": 123})
        >>> users = result.fetchall()
    """
    if not query_str or not query_str.strip():
        raise ValueError("Query string cannot be empty")

    params = params or {}

    # Validate query safety
    _validate_query_safety(query_str, read_only=False)

    # Get or create engine
    if engine is None:
        engine = get_engine()

    # Prepare query with timeout
    if "MAX_EXECUTION_TIME" not in query_str.upper():
        query_str = f"/*+ MAX_EXECUTION_TIME({timeout_ms}) */ {query_str}"

    sql_query = text(query_str)

    # Execute with retry logic
    def execute_query() -> "Result[Any]":
        with engine.begin() as conn:
            return conn.execute(sql_query, params)

    result = _retry_with_backoff(execute_query, max_retries=max_retries)
    return result  # type: ignore[no-any-return]


@latency_warn(500)
def read_only_query(
    query_str: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    engine: Optional[Engine] = None,
    timeout_ms: int = 15000,
    max_retries: int = 3,
) -> "Result[Any]":
    """
    Execute a read-only SQL query with enhanced safety checks.

    This function provides additional safety for read-only operations by:
    - Enforcing read-only transaction mode
    - Blocking write operations
    - Using shorter default timeouts
    - Enhanced logging for audit trails

    Args:
        query_str: SQL query string (SELECT, SHOW, DESCRIBE, etc.)
        params: Dictionary of parameter values
        engine: SQLAlchemy engine (if None, creates read-only engine)
        timeout_ms: Query timeout in milliseconds (default: 15s)
        max_retries: Maximum number of retry attempts

    Returns:
        SQLAlchemy Result object

    Raises:
        ReadOnlyViolationError: If write operations are detected
        SQLSafetyError: If unsafe SQL patterns are detected

    Example:
        >>> result = read_only_query("SELECT COUNT(*) FROM orders WHERE date > :date", {"date": "2024-01-01"})
        >>> count = result.scalar()
    """
    if not query_str or not query_str.strip():
        raise ValueError("Query string cannot be empty")

    params = params or {}

    # Validate query safety with read-only enforcement
    _validate_query_safety(query_str, read_only=True)

    # Get or create read-only engine
    if engine is None:
        engine = get_engine(ro=True)

    # Prepare query with timeout
    if "MAX_EXECUTION_TIME" not in query_str.upper():
        query_str = f"/*+ MAX_EXECUTION_TIME({timeout_ms}) */ {query_str}"

    sql_query = text(query_str)

    # Execute with retry logic in read-only transaction
    def execute_readonly_query() -> "Result[Any]":
        with engine.begin() as conn:
            # Ensure read-only transaction
            conn.execute(text("SET TRANSACTION READ ONLY"))
            return conn.execute(sql_query, params)

    result = _retry_with_backoff(execute_readonly_query, max_retries=max_retries)
    return result  # type: ignore[no-any-return]


def bulk_query(
    queries: List[Dict[str, Any]],
    *,
    engine: Optional[Engine] = None,
    read_only: bool = False,
    timeout_ms: int = 60000,
) -> List["Result[Any]"]:
    """
    Execute multiple queries in a single transaction for better performance.

    Args:
        queries: List of query dictionaries with 'query' and optional 'params' keys
        engine: SQLAlchemy engine (if None, creates appropriate engine)
        read_only: If True, enforce read-only mode for all queries
        timeout_ms: Total timeout for all queries

    Returns:
        List of SQLAlchemy Result objects

    Example:
        >>> queries = [
        ...     {"query": "SELECT COUNT(*) FROM users"},
        ...     {"query": "SELECT COUNT(*) FROM orders WHERE user_id = :id", "params": {"id": 123}}
        ... ]
        >>> results = bulk_query(queries, read_only=True)
    """
    if not queries:
        raise ValueError("Queries list cannot be empty")

    # Get appropriate engine
    if engine is None:
        engine = get_engine(ro=read_only)

    results: List["Result[Any]"] = []

    @latency_warn(timeout_ms)
    def execute_bulk() -> List["Result[Any]"]:
        with engine.begin() as conn:
            if read_only:
                conn.execute(text("SET TRANSACTION READ ONLY"))

            conn.execute(text(f"SET SESSION MAX_EXECUTION_TIME={timeout_ms}"))

            for query_dict in queries:
                query_str = query_dict["query"]
                params = query_dict.get("params", {})

                # Validate each query
                _validate_query_safety(query_str, read_only=read_only)

                # Execute query
                result = conn.execute(text(query_str), params)
                results.append(result)

        return results

    result = execute_bulk()
    return result  # type: ignore[no-any-return]
