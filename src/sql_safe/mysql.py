# SPDX - License - Identifier: MIT
# Copyright (c) 2025 Perday CatalogLAB™

from __future__ import annotations

from typing import Any

from sqlalchemy import text


def mysql_with_timeout(query: str, timeout_ms: int = 2000) -> Any:
    """
    Wrap a parameterized SQL query string with MySQL's MAX_EXECUTION_TIME.
    Usage:
        q = mysql_with_timeout("SELECT * FROM songs WHERE artist_id = :aid", 1500)
        conn.execute(q, {"aid": 123})
    """
    # Ensure no f - strings; user passes a literal query with placeholders
    prefix = f"/*+ MAX_EXECUTION_TIME({int(timeout_ms)}) */ "
    return text(prefix + query)
