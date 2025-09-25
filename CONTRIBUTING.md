# Contributing Guide

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

1. Clone the repository
2. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
3. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Code Quality

We maintain high code quality standards:

- **Type hints**: All functions must have type hints
- **Documentation**: All public APIs must be documented
- **Tests**: All features must have comprehensive tests
- **Formatting**: Code is formatted with Black
- **Linting**: Code is linted with Ruff
- **Type checking**: Code is type-checked with MyPy

## Testing

Run the test suite:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=src --cov-report=html
```

Run benchmarks:
```bash
pytest -m benchmark
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Update documentation if needed
7. Submit a pull request

## Code of Conduct

Please be respectful and professional in all interactions.

## Questions?

Feel free to open an issue for questions or discussion.
