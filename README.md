# SQL Safe

[![CI](https://github.com/wmoore012/sql_safe/actions/workflows/ci.yml/badge.svg)](https://github.com/wmoore012/sql_safe/actions/workflows/ci.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/wmoore012/sql_safe/blob/main/LICENSE)

> **Built for [Perday CatalogLAB](https://perdaycatalog.com)** - a live demo of a data story platform for music producers and songwriters.

SQL injection prevention and safe query execution for music analytics pipelines.

**Repo:** https://github.com/wmoore012/sql_safe
**What it does:** Validates and sanitizes dynamic SQL for artist/song/label queries so CatalogLAB never accidentally drops a table or leaks data.

## Why I Built It

Music metadata is messy. Song titles have apostrophes, quotes, and special characters. Artist names span every language and script. When building analytics queries dynamically (think: "show me all songs by 'Lil' Kim"), one bad escape can corrupt your database or open a security hole.

I built `sql_safe` to make parameterized queries foolproof for the music domain. It powers the query layer behind CatalogLAB's catalog search and rollup views.

## Key Features

- **Parameterized query builder** with automatic escaping
- **Music-domain validators** for ISRCs, UPCs, and artist identifiers
- **Batch operation support** for bulk catalog imports
- **Type hints throughout** for IDE autocomplete and mypy validation
- **Zero dependencies** beyond the Python standard library

## Installation

```bash
pip install sql-safe
```

Or clone locally:

```bash
git clone https://github.com/wmoore012/sql_safe.git
cd sql_safe
pip install -e .
```

## Quick Start

```python
from sql_safe import SafeQuery, validate_isrc

# Build a safe query with automatic parameter binding
query = SafeQuery("SELECT * FROM songs WHERE isrc = :isrc")
query.bind("isrc", validate_isrc("USUM71703861"))

# Execute safely
result = db.execute(query.sql, query.params)
```

## Performance

| Metric | Value |
|--------|-------|
| Query validation | < 1ms |
| Batch insert prep | 10K rows/sec |
| Memory overhead | Minimal |

See [BENCHMARKS.md](BENCHMARKS.md) for detailed results.

## Documentation

- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## Professional Context

Built by **Wilton Moore** for Perday Labs. This module demonstrates:

- Secure coding practices for financial/entertainment data
- Clean API design that prevents misuse by construction
- Production-grade input validation

## Contact

Questions about music data pipelines or collabs?
- LinkedIn: https://www.linkedin.com/in/wiltonmoore/
- GitHub: https://github.com/wmoore012

## License

MIT License. See [LICENSE](LICENSE) for details.
