# DBShield Development Guide

This guide covers local environment setup, dependency management, code style enforcement, and testing procedures for DBShield developers.

---

## 1. Prerequisites

- **Python**: 3.12 or newer.
- **Git**: 2.30+ configured with your author identity.

---

## 2. Setting Up Development Environment

Clone the repository and install in editable mode with development dependencies:

```bash
git clone <repository-url>
cd dbshield
python -m pip install -e ".[dev]"
```

Verify that the `dbshield` binary is active:

```bash
dbshield --version
dbshield doctor
```

---

## 3. Running Automated Tests

Run the full test suite using `pytest`:

```bash
# Run all tests
pytest

# Run with verbose output and coverage
pytest -v --cov=dbshield

# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/
```

---

## 4. Code Quality & Formatting

DBShield uses **Ruff** for high-speed linting and code formatting, and **Mypy** for strict static typing:

```bash
# Check code style and rules
ruff check src tests

# Check formatting
ruff format --check src tests

# Auto-format codebase
ruff format src tests

# Static type checking
mypy src
```

---

## 5. Pre-Commit Hooks

Install pre-commit hooks to automatically check code before committing:

```bash
pre-commit install
```
