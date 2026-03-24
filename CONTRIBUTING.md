# Contributing to container-registry-cli

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

### Prerequisites

- Python 3.9+
- Git

### Getting Started

```bash
# Clone the repository
git clone https://github.com/SanjaySundarMurthy/container-registry-cli.git
cd container-registry-cli

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\Activate.ps1  # Windows PowerShell

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=container_registry_cli --cov-report=term-missing

# Run specific test file
pytest tests/test_models.py -v
```

### Linting

```bash
# Check for lint errors
ruff check .

# Auto-fix lint errors
ruff check . --fix

# Format code
ruff format .
```

### Type Checking

```bash
mypy container_registry_cli/
```

## Project Structure

```
container_registry_cli/
├── __init__.py           # Package version
├── cli.py                # Click CLI entry point
├── demo.py               # Demo project generator
├── models.py             # Domain models (dataclasses)
├── parser.py             # YAML manifest/policy parser
├── py.typed              # PEP 561 type marker
├── analyzers/
│   ├── cleanup_engine.py # Cleanup policy evaluation
│   └── vuln_scanner.py   # Security rule scanner
└── reporters/
    ├── export_reporter.py  # JSON/HTML export
    └── terminal_reporter.py # Rich terminal output
```

## Making Changes

### Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Add or update tests for your changes
5. Ensure all tests pass: `pytest -v`
6. Ensure linting passes: `ruff check .`
7. Commit with a conventional commit message
8. Push to your fork and open a Pull Request

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new security rule REG-011
fix: correct age calculation for stale tags
docs: update README with new CLI options
test: add coverage for HTML export edge cases
ci: add CodeQL security scanning
chore: update dependencies
```

### Adding a New Security Rule

1. Add the rule ID and description to `VULN_RULES` in `analyzers/vuln_scanner.py`
2. Add the detection logic in `scan_images()`
3. Add tests in `tests/test_analyzers.py`
4. Update the README security rules table

### Adding a New CLI Command

1. Add the command function in `cli.py` using `@main.command()`
2. Add tests in `tests/test_cli.py`
3. Update the README CLI reference section

## Code Style

- Follow PEP 8 (enforced by ruff)
- Use type hints for all function signatures
- Keep line length ≤ 100 characters
- Use dataclasses for domain models
- Write docstrings for public functions and classes

## Reporting Issues

- Use the [Bug Report](https://github.com/SanjaySundarMurthy/container-registry-cli/issues/new?template=bug_report.md) template for bugs
- Use the [Feature Request](https://github.com/SanjaySundarMurthy/container-registry-cli/issues/new?template=feature_request.md) template for enhancements

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
