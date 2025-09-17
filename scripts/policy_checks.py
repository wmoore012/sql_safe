#!/usr/bin/env python3
import sys
from pathlib import Path
from typing import Iterable, List

EM_DASH = "\u2014"
SQL_WORDS = ("SELECT ", "INSERT ", "UPDATE ", "DELETE ")


def has_unsafe_sql_in_fstring(text: str) -> bool:
    return ('f"' in text or "f'" in text) and any(w in text for w in SQL_WORDS)


def scan(paths: Iterable[str]) -> List[str]:
    violations: List[str] = []
    for p in paths:
        path = Path(p)
        files = [*path.rglob("*.py")] if path.is_dir() else [path]
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except Exception:
                continue
            if EM_DASH in text:
                violations.append(f"em-dash-found: {f}")
            if has_unsafe_sql_in_fstring(text):
                violations.append(f"unsafe-sql-fstring: {f}")
    return violations


if __name__ == "__main__":
    roots = sys.argv[1:] or ["src", "tests"]
    v = scan(roots)
    if v:
        print("Policy violations:")
        for line in v:
            print(" -", line)
        sys.exit(1)
    print("Policy OK")
    sys.exit(0)
