# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Perday CatalogLAB™

"""
Safe SQL query execution with injection prevention and performance monitoring.

This module provides secure database operations with automatic parameterization,
read - only enforcement, timeout protection, and comprehensive logging.
"""

from __future__ import annotations

import logging
import os
import re
import time
from functools import wraps
from typing import Any, Callable
from urllib.parse import quote

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.engine.result import Result
from sqlalchemy.exc import (
    DisconnectionError,
    OperationalError,
    SQLAlchemyError,
)

logger = logging.getLogger(__name__)


class SQLSafetyError(Exception):
    """Raised when unsafe SQL patterns are detected."""

    pass


class ReadOnlyViolationError(Exception):
    """Raised when write operations are attempted in read - only mode."""

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
                    logger.warning(
                        "🐢 Slow query detected: %.1fms (threshold: %dms)", elapsed_ms, ms
                    )
                else:
                    logger.debug("Query completed in %.1fms", elapsed_ms)

                return result
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                logger.error("Query failed after %.1fms: %s", elapsed_ms, type(e).__name__)
                raise

        return wrapper

    return decorator


def get_engine(schema: str = "PUBLIC", *, ro: bool = False, echo: bool = False) -> Engine:
    """
    Get a SQLAlchemy engine with security and performance optimizations.

    Args:
        schema: Database schema to connect to ("PUBLIC" or "PRIVATE")
        ro: If True, configure for read - only access
        echo: If True, enable SQL query logging (WARNING: includes connection info)

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
        user = os.getenv("DB_USER")
        password = os.getenv("DB_PASS")

        if not user:
            raise ValueError("DB_USER environment variable must be set")
        if not password:
            raise ValueError("DB_PASS environment variable must be set")

        if schema == "PUBLIC":
            db_name = os.getenv("DB_NAME_PUBLIC", "icatalog_public")
        else:  # PRIVATE
            db_name = os.getenv("DB_NAME_PRIVATE", "icatalog")

        safe_user = quote(user, safe="")
        safe_password = quote(password, safe="")
        url = f"mysql+pymysql://{safe_user}:{safe_password}@{host}:{port}/{db_name}?charset=utf8mb4"

    # Add connection/query timeouts (safe defaults)
    def _append_if_missing(u: str, key: str, value: str) -> str:
        sep = "&" if "?" in u else "?"
        return u if f"{key}=" in u else f"{u}{sep}{key}={value}"

    # Add read-only parameters if requested
    if ro:
        url = _append_if_missing(url, "connect_timeout", "5")
        url = _append_if_missing(url, "read_timeout", "15")
    else:
        url = _append_if_missing(url, "connect_timeout", "5")
        url = _append_if_missing(url, "read_timeout", "30")
        url = _append_if_missing(url, "write_timeout", "15")

    # Create engine with optimized settings
    engine = create_engine(
        url,
        pool_pre_ping=True,
        pool_recycle=3600,  # Recycle connections every hour
        pool_size=5,  # Connection pool size
        max_overflow=10,  # Max overflow connections
        echo=echo,
    )

    # Set session - level timeouts
    try:
        with engine.begin() as conn:
            conn.execute(text("SET SESSION MAX_EXECUTION_TIME=30000"))  # 30 second default
            conn.execute(text("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_BACKSLASH_ESCAPES'"))
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
        ReadOnlyViolationError: If write operations are detected in read - only mode
    """
    # Normalize early for simple checks when needed

    def _strip_strings_and_comments(sql: str) -> str:
        """Remove string literals and comments to safely scan SQL structure.

        This strips:
        - single-quoted strings with backslash or doubled-quote escapes
        - double-quoted strings (rare in MySQL for strings, but keep safe)
        - backtick-quoted identifiers
        - line comments starting with -- and #
        - block comments /* ... */ (not nested)
        """
        i = 0
        n = len(sql)
        out: list[str] = []
        while i < n:
            ch = sql[i]
            nxt = sql[i + 1] if i + 1 < n else ""

            # Line comments -- and #
            if ch == "-" and nxt == "-":
                # consume until end of line
                i += 2
                while i < n and sql[i] != "\n":
                    i += 1
                continue
            if ch == "#":
                i += 1
                while i < n and sql[i] != "\n":
                    i += 1
                continue

            # Block comment /* ... */
            if ch == "/" and nxt == "*":
                i += 2
                while i + 1 < n and not (sql[i] == "*" and sql[i + 1] == "/"):
                    i += 1
                i += 2 if i + 1 < n else 0
                continue

            # Backtick identifiers
            if ch == "`":
                i += 1
                while i < n:
                    if sql[i] == "`":
                        i += 1
                        break
                    i += 1
                continue

            # Single or double quoted strings
            if ch in ("'", '"'):
                quote = ch
                i += 1
                while i < n:
                    c = sql[i]
                    # handle backslash escapes and doubled quotes
                    if c == "\\":
                        i += 2
                        continue
                    if c == quote:
                        # doubled quote escape (e.g., '' inside single quote)
                        if i + 1 < n and sql[i + 1] == quote:
                            i += 2
                            continue
                        i += 1
                        break
                    i += 1
                continue

            out.append(ch)
            i += 1
        return "".join(out)

    def _has_multiple_statements(sql: str) -> bool:
        sanitized = _strip_strings_and_comments(sql)
        stripped = sanitized.strip()
        # Allow a single trailing semicolon
        if stripped.endswith(";"):
            stripped = stripped[:-1]
        return ";" in stripped

    def _contains_write_ops(sql: str) -> bool:
        sanitized = _strip_strings_and_comments(sql).upper()
        write_ops = [
            r"\bINSERT\b",
            r"\bUPDATE\b",
            r"\bDELETE\b",
            r"\bREPLACE\b",
            r"\bMERGE\b",
            r"\bCALL\b",
            r"\bLOCK\s+TABLES\b",
            r"\bUNLOCK\s+TABLES\b",
        ]
        for pattern in write_ops:
            if re.search(pattern, sanitized, re.IGNORECASE):
                return True
        # SELECT ... FOR UPDATE (not allowed in read-only)
        if re.search(r"\bFOR\s+UPDATE\b", sanitized, re.IGNORECASE):
            return True
        return False

    # Disallow multiple statements to prevent stacked queries
    if _has_multiple_statements(query_str):
        raise SQLSafetyError("Multiple SQL statements detected; only a single statement is allowed")

    # Pre-strip literals/comments once for structural checks
    sanitized_for_scan = _strip_strings_and_comments(query_str)

    # Check for dangerous patterns
    dangerous_patterns = [
        re.compile(r"\bDROP\b", re.IGNORECASE),
        re.compile(r"\bTRUNCATE\b", re.IGNORECASE),
        re.compile(r"\bALTER\b", re.IGNORECASE),
        re.compile(r"\bCREATE\b", re.IGNORECASE),
        re.compile(r"\bGRANT\b", re.IGNORECASE),
        re.compile(r"\bREVOKE\b", re.IGNORECASE),
        re.compile(r"LOAD_FILE", re.IGNORECASE),
        re.compile(r"INTO\s+OUTFILE", re.IGNORECASE),
        re.compile(r"INTO\s+DUMPFILE", re.IGNORECASE),
        re.compile(r"UNION\s+SELECT.*FROM\s+INFORMATION_SCHEMA", re.IGNORECASE | re.DOTALL),
        re.compile(r"UNION\s+SELECT.*FROM\s+MYSQL", re.IGNORECASE | re.DOTALL),
        re.compile(r"\bDELIMITER\b", re.IGNORECASE),
        re.compile(r"\bPREPARE\b", re.IGNORECASE),
        re.compile(r"\bEXECUTE\b\s+\w+", re.IGNORECASE),
        re.compile(r"\bDEALLOCATE\s+PREPARE\b", re.IGNORECASE),
        re.compile(r"\bLOAD\s+DATA\b", re.IGNORECASE),
    ]

    for pattern in dangerous_patterns:
        if pattern.search(sanitized_for_scan):
            raise SQLSafetyError(f"Dangerous SQL pattern detected: {pattern.pattern}")

    # Disallow UNION SELECT by default (prevent result-shape inference/injection)
    if re.search(r"\bUNION\s+SELECT\b", sanitized_for_scan, re.IGNORECASE):
        raise SQLSafetyError("Dangerous SQL pattern detected: UNION SELECT")

    # Check for write operations in read-only mode
    if read_only:
        # Block classic write verbs even if preceded by comments/CTEs
        if _contains_write_ops(query_str):
            raise ReadOnlyViolationError(
                "Write operation detected in read-only mode (INSERT/UPDATE/DELETE/REPLACE/MERGE/CALL/LOCK/UNLOCK/SELECT FOR UPDATE)"
            )

    # Enforce parameterized queries — use named binds for any query with literals
    if "'" in query_str and not re.search(r":\w+", query_str):
        raise SQLSafetyError(
            "Query contains literal quotes without parameters; use named bind parameters (:name)."
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
        except (OperationalError, DisconnectionError, ConnectionError) as e:
            last_exception = e
            if attempt == max_retries:
                logger.error("Query failed after %d retries: %s", max_retries, type(e).__name__)
                break
            delay = base_delay * (2**attempt)  # Exponential backoff
            logger.warning(
                "Query attempt %d failed, retrying in %.2fs: %s",
                attempt + 1,
                delay,
                type(e).__name__,
            )
            time.sleep(delay)
        except SQLAlchemyError as e:
            logger.error("Query failed with non-retryable error: %s", type(e).__name__)
            raise

    if last_exception:
        raise last_exception
    raise RuntimeError("Function failed without exception")


# Heuristic: when SQL likely needs parameters (filters/mutations/comparisons)
def _requires_parameters_raw(sql: str) -> bool:
    upper = sql.upper()
    return bool(
        re.search(r"\b(WHERE|HAVING|VALUES|SET|IN\s*\(|LIKE|BETWEEN|LIMIT|OFFSET)\b", upper)
        or re.search(r"[<>!=]=|\s=\s", upper)
    )


@latency_warn(500)  # Warn for queries taking longer than 500ms
def query(
    query_str: str,
    params: dict[str, Any] | None = None,
    *,
    engine: Engine | None = None,
    timeout_ms: int = 30000,
    max_retries: int = 3,
) -> Result[Any]:
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

    # Require parameters when SQL contains filters/comparisons
    if _requires_parameters_raw(query_str) and (not params or not re.search(r":\w+", query_str)):
        raise SQLSafetyError(
            "Parameters required for filtered queries; use named bind parameters (:name) and provide params."
        )

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
    def execute_query() -> Result[Any]:
        with engine.begin() as conn:
            return conn.execute(sql_query, params)

    result = _retry_with_backoff(execute_query, max_retries=max_retries)
    return result  # type: ignore[no - any - return]


@latency_warn(500)
def read_only_query(
    query_str: str,
    params: dict[str, Any] | None = None,
    *,
    engine: Engine | None = None,
    timeout_ms: int = 15000,
    max_retries: int = 3,
) -> Result[Any]:
    """
    Execute a read - only SQL query with enhanced safety checks.

    This function provides additional safety for read - only operations by:
    - Enforcing read - only transaction mode
    - Blocking write operations
    - Using shorter default timeouts
    - Enhanced logging for audit trails

    Args:
        query_str: SQL query string (SELECT, SHOW, DESCRIBE, etc.)
        params: Dictionary of parameter values
        engine: SQLAlchemy engine (if None, creates read - only engine)
        timeout_ms: Query timeout in milliseconds (default: 15s)
        max_retries: Maximum number of retry attempts

    Returns:
        SQLAlchemy Result object

    Raises:
        ReadOnlyViolationError: If write operations are detected
        SQLSafetyError: If unsafe SQL patterns are detected

    Example:
        >>> result = read_only_query("SELECT COUNT(*) FROM orders WHERE date > :date", {"date": "2025 - 01 - 01"})
        >>> count = result.scalar()
    """
    if not query_str or not query_str.strip():
        raise ValueError("Query string cannot be empty")

    params = params or {}

    # Require parameters when SQL contains filters/comparisons
    if _requires_parameters_raw(query_str) and (not params or not re.search(r":\w+", query_str)):
        raise SQLSafetyError(
            "Parameters required for filtered queries; use named bind parameters (:name) and provide params."
        )

    # Validate query safety with read - only enforcement
    _validate_query_safety(query_str, read_only=True)

    # Get or create read - only engine
    if engine is None:
        engine = get_engine(ro=True)

    # Prepare query with timeout
    if "MAX_EXECUTION_TIME" not in query_str.upper():
        query_str = f"/*+ MAX_EXECUTION_TIME({timeout_ms}) */ {query_str}"

    sql_query = text(query_str)

    # Execute with retry logic in read - only transaction
    def execute_readonly_query() -> Result[Any]:
        with engine.begin() as conn:
            # Ensure read - only transaction
            conn.execute(text("SET TRANSACTION READ ONLY"))
            return conn.execute(sql_query, params)

    result = _retry_with_backoff(execute_readonly_query, max_retries=max_retries)
    return result  # type: ignore[no - any - return]


def bulk_query(
    queries: list[dict[str, Any]],
    *,
    engine: Engine | None = None,
    read_only: bool = False,
    timeout_ms: int = 60000,
) -> list[Result[Any]]:
    """
    Execute multiple queries in a single transaction for better performance.

    Args:
        queries: List of query dictionaries with 'query' and optional 'params' keys
        engine: SQLAlchemy engine (if None, creates appropriate engine)
        read_only: If True, enforce read - only mode for all queries
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

    results: list[Result[Any]] = []

    @latency_warn(timeout_ms)
    def execute_bulk() -> list[Result[Any]]:
        with engine.begin() as conn:
            if read_only:
                conn.execute(text("SET TRANSACTION READ ONLY"))

            conn.execute(text(f"SET SESSION MAX_EXECUTION_TIME={timeout_ms}"))

            for query_dict in queries:
                query_str = query_dict["query"]
                params = query_dict.get("params", {})

                # Require parameters when SQL contains filters/comparisons
                if _requires_parameters_raw(query_str) and (
                    not params or not re.search(r":\w+", query_str)
                ):
                    raise SQLSafetyError(
                        "Parameters required for filtered queries; use named bind parameters (:name) and provide params."
                    )

                # Validate each query
                _validate_query_safety(query_str, read_only=read_only)

                # Execute query
                result = conn.execute(text(query_str), params)

                results.append(result)

        return results

    result = execute_bulk()
    return result  # type: ignore[no - any - return]


# Public helper utilities for safe identifiers and pagination
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def safe_ident(name: str, allowed: set[str] | None = None) -> str:
    """Validate an SQL identifier (e.g., column/table alias).

    - Must match [_A-Za-z][_A-Za-z0-9]*
    - If allowed set provided, must be a member
    """
    if not name or not _IDENT_RE.match(name):
        raise SQLSafetyError("Invalid identifier")
    if allowed is not None and name not in allowed:
        raise SQLSafetyError("Identifier not allowed")
    return name


def safe_order_by(column: str, allowed: set[str]) -> str:
    """Validate ORDER BY column and optional direction.

    Examples: "created_at", "created_at DESC"
    """
    parts = column.strip().split()
    if not parts:
        raise SQLSafetyError("Empty ORDER BY")
    col = parts[0]
    direction = parts[1].upper() if len(parts) > 1 else "ASC"
    if direction not in {"ASC", "DESC"}:
        raise SQLSafetyError("Invalid ORDER BY direction")
    safe_ident(col, allowed)
    return f"{col} {direction}"


def safe_limit(n: int, max_n: int = 1000) -> int:
    if n < 0:
        raise SQLSafetyError("LIMIT must be non-negative")
    return min(n, max_n)


def safe_offset(n: int, max_n: int = 100000) -> int:
    if n < 0:
        raise SQLSafetyError("OFFSET must be non-negative")
    return min(n, max_n)
