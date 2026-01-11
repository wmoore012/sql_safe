from __future__ import annotations

"""Test configuration for the sql-safe package.

Pytest is executed from the project root of the sql-injection-guard module
(``oss/sql-injection-guard``) while the actual package code lives under the
``src/`` layout.  To make ``import sql_safe`` work without requiring an
editable install, we add the local ``src`` directory to ``sys.path`` with a
high precedence.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
