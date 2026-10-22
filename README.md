# DBShield

**DBShield** is a professional, modular CLI security framework designed for discovering, analyzing, and testing database-related vulnerabilities (SQL Injection, NoSQL Injection, authentication weaknesses) in web applications.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: Mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](https://mypy-lang.org/)
[![Tests: Pytest](https://img.shields.io/badge/tests-45%20passed-brightgreen.svg)](#)

---

> [!WARNING]
> **Authorized Security Testing Only**: DBShield is engineered solely for authorized security assessments, penetration testing, defensive auditing, and vulnerability research conducted with explicit, written authorization from the target system owner. Unauthorized testing against systems without permission is illegal and strictly prohibited.

---

## Project Status

- **Current Phase**: **Phase 1 — Project Foundation and Core Architecture** (Completed & Verified)
- **Roadmap**: 10 Phases leading to advanced database vulnerability detection and Burp Suite integration. See [docs/roadmap.md](docs/roadmap.md).

### Implemented Functionality (Phase 1)
- **Standard Python Package & CLI**: Installable package (`dbshield`) built with Typer following Linux CLI standards.
- **Centralized Configuration**: `pydantic-settings` with environment variable validation and safe parameter exposure.
- **Foundational Data Models**: Validated `Target` and `Scan` domain models with strict URL normalization and port/scheme validation.
- **Target Scope Management**: Robust `ScopeManager` enforcing exact host matching, subdomain policy guards, similarly-named attacker domain rejections, and redirect destination pre-validation.
- **Safe Scope-Aware HTTP Client**: Built on `httpx` with timeout budgets, redirect limits, pre-flight scope assertions, and sensitive-data redaction.
- **Centralized Logging & Redaction**: Automated scrubbing of passwords, authorization tokens, cookies, JWTs, and GitHub tokens from log outputs.
- **Diagnostic & Inspection Commands**:
  - `dbshield doctor`: Environment, Python runtime, and configuration readiness checks.
  - `dbshield info`: Safe configuration summary and runtime metadata.
  - `dbshield inspect --url <URL>`: Passive URL syntax and scope evaluation (zero network calls).

### Out of Scope in Phase 1 (Planned for Future Phases)
Active vulnerability scanning, payload execution (SQLi/NoSQLi), crawling, authentication workflows, report generation, and Burp Suite integrations are explicitly scheduled for Phases 2–10.

---

## Requirements

- **Python**: Version 3.12 or newer.
- **Operating System**: Linux (Ubuntu 22.04/24.04 recommended), macOS, or Windows 11.

---

## Installation

### Editable Installation (Development)

Clone the repository and install with development dependencies:

```bash
git clone <repository-url>
cd dbshield
python -m pip install -e ".[dev]"
```

Verify installation:

```bash
dbshield --version
```

---

## CLI Usage

### 1. View Help and Available Commands
```bash
dbshield --help
```

### 2. Run Environment Diagnostics (`doctor`)
Verifies Python version, configuration parsing, and workspace directory write access:
```bash
dbshield doctor
```

### 3. Display Framework & Configuration Information (`info`)
Displays active settings without exposing sensitive credentials:
```bash
dbshield info
```

### 4. Inspect Target URL (`inspect`)
Performs passive URL validation, scheme verification, and scope evaluation without sending any network packets:
```bash
dbshield inspect --url https://example.com/login?service=auth
```

---

## Configuration

Configuration is managed via environment variables or a local `.env` file (see `.env.example`):

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DBSHIELD_HTTP_TIMEOUT` | Request timeout in seconds | `10.0` |
| `DBSHIELD_MAX_REDIRECTS` | Maximum redirects to follow | `5` |
| `DBSHIELD_USER_AGENT` | HTTP User-Agent header | `DBShield/0.1.0 ...` |
| `DBSHIELD_LOG_LEVEL` | Log severity (DEBUG, INFO, WARN, ERROR) | `INFO` |
| `DBSHIELD_LOG_FILE` | Optional path to write log file | `None` |
| `DBSHIELD_DATA_DIR` | Local cache and session storage directory | `~/.local/share/dbshield` |
| `DBSHIELD_ALLOWED_HOSTS` | JSON array of authorized domains/hosts | `[]` |
| `DBSHIELD_ALLOW_SUBDOMAINS`| Whether subdomains are in-scope | `false` |
| `DBSHIELD_RATE_LIMIT` | Max requests per second | `10.0` |

---

## Development and Testing

Execute the test suite (45 unit and integration tests):
```bash
pytest
```

Run linting and code style checks:
```bash
ruff check src tests
ruff format --check src tests
```

Run static type analysis:
```bash
mypy src
```

---

## Repository Structure

```text
dbshield/
├── README.md                 # Project overview and quickstart
├── pyproject.toml            # Build metadata, dependencies, and tool settings
├── .gitignore                # Exclusion rules for artifacts and secrets
├── .pre-commit-config.yaml   # Pre-commit hook definitions
├── .env.example              # Safe configuration template
├── CHANGELOG.md              # Historical ledger of changes
├── CONTRIBUTING.md           # Contribution guidelines
├── LICENSE                   # MIT License
├── docs/                     # Architectural documentation
│   ├── architecture.md       # Modular layered architecture design
│   ├── development.md        # Contributor and development workflow
│   ├── roadmap.md            # 10-phase project evolution roadmap
│   └── phases/
│       └── phase-01.md       # Phase 1 completion and verification report
├── src/
│   └── dbshield/
│       ├── __init__.py       # Package metadata
│       ├── __main__.py       # Module entry point
│       ├── cli.py            # Typer CLI interface
│       ├── config.py         # Pydantic Settings management
│       ├── exceptions.py     # Structured exception hierarchy
│       ├── logging_config.py # Structured logging and secret redaction
│       ├── models/           # Domain data models (Target, Scan)
│       ├── scope/            # ScopeManager boundary enforcement
│       └── http/             # Scope-aware SafeHTTPClient
└── tests/
    ├── unit/                 # Unit tests (config, models, scope, logging, cli)
    └── integration/          # HTTP client integration tests with mock transport
```

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
