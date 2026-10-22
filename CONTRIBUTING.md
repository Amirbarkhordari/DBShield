# Contributing to DBShield

Thank you for your interest in contributing to DBShield. This document outlines the development practices, quality checks, and contribution workflows required for this project.

---

## 1. Development Principles

1. **Safety & Scope by Default**: Security tools must operate only on authorized targets. Never introduce features that bypass scope validation.
2. **Decoupled Architecture**: Domain logic must remain independent of CLI rendering and I/O adapters.
3. **Stream Discipline**: Machine-readable data belongs on `stdout`; diagnostics, progress, and logs belong on `stderr`.
4. **Honest Reporting**: Never fake scan results, progress metrics, or test outputs.

---

## 2. Environment Setup

1. **Prerequisites**: Python 3.12+ and Git.
2. **Clone & Install**:
   ```bash
   git clone <repository-url>
   cd dbshield
   python -m pip install -e ".[dev]"
   ```
3. **Verify Setup**:
   ```bash
   dbshield doctor
   ```

---

## 3. Code Quality Standards

Before submitting changes, ensure all checks pass:

- **Testing**:
  ```bash
  pytest
  ```
- **Linting & Formatting**:
  ```bash
  ruff check src tests
  ruff format --check src tests
  ```
- **Static Type Checking**:
  ```bash
  mypy src
  ```

---

## 4. Commit Message Conventions

We adhere to [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(scope): add new capability`
- `fix(scope): resolve bug`
- `refactor(scope): internal restructuring`
- `test(scope): add test cases`
- `docs(scope): update documentation`
- `chore: maintenance and dependencies`

---

## 5. Security & Secret Disclosure

Never commit real credentials, access tokens, private keys, or passwords. All tests must use mocked responses or local fixtures.
