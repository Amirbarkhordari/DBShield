# DBShield

**DBShield** is a professional, modular CLI security framework designed for discovering, analyzing, and testing database-related vulnerabilities (SQL Injection, NoSQL Injection, authentication weaknesses) in web applications.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: Mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](https://mypy-lang.org/)
[![Tests: Pytest](https://img.shields.io/badge/tests-291%20passed-brightgreen.svg)](#)

---

> [!WARNING]
> **Authorized Security Testing Only**: DBShield is engineered solely for authorized security assessments, penetration testing, defensive auditing, and vulnerability research conducted with explicit, written authorization from the target system owner. Unauthorized testing against systems without permission is illegal and strictly prohibited.

---

## Project Status

- **Current Phase**: **Phase 6 — Payload Management and Test Execution Engine** (Completed & Verified)
- **Roadmap**: 10 Phases leading to advanced database vulnerability detection and Burp Suite integration. See [docs/roadmap.md](docs/roadmap.md).

### Implemented Functionality

#### Phase 1: Foundation and Core Architecture
- **Standard Python Package & CLI**: Installable package (`dbshield`) built with Typer following Linux CLI design standards.
- **Centralized Configuration**: `pydantic-settings` with environment variable validation, lenient list parsing, and safe parameter exposure.
- **Foundational Data Models**: Validated `Target` and `Scan` domain models with strict URL normalization and port/scheme validation.
- **Target Scope Management**: Robust `ScopeManager` enforcing exact host matching, subdomain policy guards, similarly-named attacker domain rejections, and redirect destination pre-validation.
- **Safe Scope-Aware HTTP Client**: Built on `httpx` with timeout budgets, redirect limits, pre-flight scope assertions, and sensitive-data redaction.
- **Centralized Logging & Redaction**: Automated scrubbing of passwords, authorization tokens, cookies, JWTs, and API tokens from log outputs.
- **Diagnostic Commands**:
  - `dbshield doctor`: Environment, Python runtime, and configuration readiness checks.
  - `dbshield info`: Safe configuration summary and runtime metadata.
  - `dbshield inspect --url <URL>`: Passive URL syntax and scope evaluation (zero network calls).

#### Phase 2: Login Page Discovery Engine
- **Dedicated Discovery Command (`dbshield discover`)**:
  - Validates URL syntax and scope authorization before any network transmission.
  - Safe, minimal page retrieval using the scope-enforcing `SafeHTTPClient`.
  - Tolerant HTML parsing (`HTMLFormParser`) extracting forms, actions, methods, encodings, and control inventories.
  - Resolves relative form actions, strips non-transmittable URL fragments, and defaults missing actions to the document URL per HTML standards.
  - Rule-based heuristic classification (`DiscoveryClassifier`) identifying username, email, password, OTP, and anti-CSRF fields.
  - Explanatory page classification (`LOGIN_FORM_DETECTED`, `MULTIPLE_LOGIN_FORMS`, `LOGIN_INPUTS_WITHOUT_FORM`, `NO_LOGIN_FORM_DETECTED`).
  - Action destination boundary validation: detects out-of-scope actions and marks them without sending any requests to them.
  - Rich human-readable terminal reports and deterministic machine-readable JSON exports (`--format json`, `--output <path>`, `--overwrite`).

#### Phase 3: HTTP Request Handling and Authentication Management
- **Dedicated Request Command (`dbshield request`)**:
  - Controlled, scope-verified outbound HTTP requests with explicit method configuration (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).
  - Configurable request headers, query parameters, form data, and JSON payloads.
  - Authentication profiles: unauthenticated, Bearer token, HTTP Basic (Base64), custom headers, and session cookies.
  - Target-bound session management (`SessionManager`) ensuring strict origin isolation.
  - Cross-origin redirect credential stripping: sensitive `Authorization` headers and `Cookie` values are scrubbed when redirecting to a different origin.
  - Response memory safety: bounded response bodies with `max_response_size_bytes` and truncation indicators.
  - Case-insensitive response headers (`CaseInsensitiveDict`) and `httpx.Response` duck-typing compatibility (`.text`, `.content`, `.json()`).
  - Strict zero-secret guarantee: passwords, tokens, and cookies are masked as `[REDACTED]` in terminal reports, logs, and JSON exports.

#### Phase 4: SQL Injection Detection Engine
- **Dedicated SQLi Command (`dbshield sqli`)**:
  - Controlled, defensive testing of explicitly selected, in-scope parameters.
  - Multi-sample baseline response characterization (`BaselineCharacterizer`) verifying status and content stability.
  - High-precision error-based SQL injection detector (`ErrorDetector`) with signature catalog across 6 database families (MySQL, PostgreSQL, SQLite, MSSQL, Oracle, Generic SQL).
  - Explicit generic error differentiation: HTTP 500 / 400 errors without database error signatures are never misclassified as SQL injection.
  - Pre-existing baseline error filtering: discards signatures already present before testing began.
  - Boolean differential response analysis (`DifferentialDetector`) with dynamic element normalization (masking timestamps, CSRF tokens, UUIDs, epochs).
  - Safety firewall: sensitive parameters (`password`, `token`, `csrf`, `secret`, `otp`) are automatically skipped.
  - Offline response fixture analysis (`--fixture <path>`): zero-network laboratory validation from captured JSON response fixtures.
  - Strict finding states: distinguishes `POTENTIAL_INDICATOR` (unconfirmed candidate finding) from `NO_INDICATOR` (does not prove secure), `INCONCLUSIVE`, `SKIPPED`, `BLOCKED_BY_SCOPE`, and `ERROR`.

#### Phase 5: NoSQL Injection Detection Engine
- **Dedicated NoSQLi Command (`dbshield nosqli`)**:
  - Controlled, defensive testing of candidate parameters for NoSQL injection.
  - Recursive nested JSON parameter extraction discovering candidate key paths (e.g. `filter.user_id`).
  - Isolated JSON deep mutation preserving all sibling fields and outer schema structure.
  - Error-based detector (`NoSQLErrorDetector`) with signature catalog for MongoDB (operator rejection, JavaScript `$where`, PyMongo errors, BSON exceptions, Mongoose CastError, regex errors), CouchDB (view compilation, Mango selectors), and generic document stores.
  - MongoDB ObjectId normalization: masks 24-hex-character ObjectIds (`[DYNAMIC_OBJECTID]`) to prevent artificial divergence in similarity calculations.
  - Operator and boolean differential detector (`NoSQLDifferentialDetector`) evaluating paired truthy/falsy queries.
  - Offline response fixture analysis (`--fixture <path>`): zero-network laboratory validation from captured JSON fixtures.
  - Safety firewall: sensitive parameters (`password`, `token`, `csrf`, `secret`, `otp`) are automatically skipped.

#### Phase 6: Payload Management and Test Execution Engine
- **Centralized Payload Catalog (`PayloadCatalog`)**:
  - Curated, typed, immutable `SecurityPayload` catalog decoupled from orchestration logic.
  - Deterministic filtering by engine, category, location, technique, provider family, risk level, and tags.
  - Integrity validation (`validate_catalog()`) verifying reciprocal relationships for paired differential tests.
- **Isolated Request Mutation (`PayloadTransformer`)**:
  - Safe parameter mutation across query parameters (flat, repeated, Express bracket notation), URL-encoded form data, and nested JSON structures (dot-paths, array indices).
  - Deep cloning guarantees caller-owned request structures are never mutated in place.
- **Centralized Execution Policies & Budget Enforcement (`ExecutionPolicy`, `ExecutionBudgetTracker`)**:
  - Global and per-parameter request ceilings preventing resource exhaustion.
  - Automatic exclusion of sensitive fields (`password`, `token`, `csrf`, `secret`, `session`).
  - Cooperative cancellation and per-request timeouts.
- **Engine Adapters (`SQLiExecutionAdapter`, `NoSQLiExecutionAdapter`)**:
  - Typed adapters invoking Phase 4 and 5 detectors without duplicating vulnerability logic.
- **Reusable Test Execution Orchestrator (`TestExecutionOrchestrator`)**:
  - Centralized lifecycle coordination: scope validation, parameter extraction, baseline profiling, isolated variant generation, bounded execution, and structured result tracking.
  - Offline response fixture analysis (`execute_offline_fixture`) for zero-network validation.
- **Dedicated CLI Commands**:
  - `dbshield payloads`: list, filter, inspect, and validate payload definitions.
  - `dbshield execute`: run multi-engine test runs across online targets or offline JSON fixtures.

### Out of Scope in Phase 6 (Planned for Future Phases)
Database extraction, table/collection dumping, data modification, automated exploitation, credential brute-forcing, whole-app crawling, evidence corroboration and false-positive elimination (Phase 7), and Burp Suite extension bindings (Phase 10).

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

### 5. Discover and Analyze Login Page (`discover`)

#### Human-Readable Terminal Summary
```bash
dbshield discover --url https://app.example.com/login
```

#### Export Structured Machine-Readable JSON
```bash
dbshield discover \
  --url https://app.example.com/login \
  --format json \
  --output ./discovery-results.json \
  --overwrite
```

#### Command Options
- `--url`, `-u`: Required target URL to analyze.
- `--format`, `-f`: Output format (`text` or `json`, default `text`).
- `--output`, `-o`: File path to save discovery output.
- `--overwrite`: Overwrite existing output file safely.
- `--timeout`, `-t`: Override default request timeout budget in seconds.

### 3. Safe HTTP Request & Authentication (`dbshield request`)

Send a controlled, scope-verified HTTP request and report response/auth status:

#### Unauthenticated GET Request
```bash
dbshield request --url https://app.example.com/api/v1/health
```

#### Bearer Token Authenticated Request
```bash
dbshield request \
  --url https://app.example.com/api/v1/user \
  --auth-type bearer \
  --token "auth-token-xyz" \
  --format json
```

#### HTTP Basic Authenticated Request
```bash
dbshield request \
  --url https://app.example.com/admin \
  --method GET \
  --auth-type basic \
  --username admin \
  --password "admin-pass"
```

#### Request Command Options
- `--url`, `-u`: Target endpoint URL (required).
- `--method`, `-m`: HTTP method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, default `GET`).
- `--header`, `-H`: Custom header in `'Name: Value'` format (repeatable).
- `--data`, `-d`: Form / raw text payload.
- `--json`, `-j`: Raw JSON payload string.
- `--auth-type`, `-a`: Auth mechanism (`none`, `bearer`, `basic`, `header`, `cookie`, default `none`).
- `--token`: Bearer authentication token.
- `--username`, `-U`: HTTP Basic username.
- `--password`, `-P`: HTTP Basic password.
- `--cookie`, `-C`: Session cookie in `'name=value'` format (repeatable).
- `--format`, `-f`: Output format (`text` or `json`, default `text`).
- `--output`, `-o`: File path to save results.
- `--overwrite`: Overwrite existing destination file.

### 4. SQL Injection Assessment (`dbshield sqli`)

Perform controlled, non-destructive SQL injection detection over in-scope endpoints or response fixtures:

#### Online Target Assessment
```bash
dbshield sqli --url https://app.example.com/items?cat=books&page=1
```

#### Test a Specific Candidate Parameter
```bash
dbshield sqli \
  --url https://app.example.com/search?q=security \
  --param q \
  --max-param-budget 6
```

#### Authenticated Assessment with Export
```bash
dbshield sqli \
  --url https://app.example.com/api/v1/profile?user_id=10 \
  --auth-type bearer \
  --token "session-bearer-token" \
  --format json \
  --output ./sqli-results.json \
  --overwrite
```

#### Offline Laboratory Fixture Assessment (Zero Network Traffic)
```bash
dbshield sqli --fixture ./tests/fixtures/sqli_sample.json
```

#### SQLi Command Options
- `--url`, `-u`: Target URL to assess (required unless `--fixture` is specified).
- `--fixture`: Path to JSON file containing captured baseline and test responses for offline laboratory testing.
- `--param`, `-p`: Specific parameter name to test (defaults to all eligible parameters).
- `--method`, `-m`: HTTP method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, default `GET`).
- `--data`, `-d`: Raw or URL-encoded form data body.
- `--json`, `-j`: Raw JSON formatted request body.
- `--auth-type`: Authentication method (`none`, `bearer`, `basic`, `header`, `cookie`, default `none`).
- `--token`: Bearer authentication token.
- `--username`: HTTP Basic username.
- `--password`: HTTP Basic password.
- `--cookie`: Session cookie string (`session=xyz`).
- `--timeout`: Per-request timeout budget in seconds.
- `--max-budget`: Total request budget ceiling across entire scan (default: 50).
- `--max-param-budget`: Request budget ceiling per candidate parameter (default: 8).
- `--disable-differential`: Disable boolean differential testing (run error-based only).
- `--format`, `-f`: Output format (`text` or `json`, default `text`).
- `--output`, `-o`: File path to export results.
- `--overwrite`: Overwrite destination output file if it exists.

### 5. NoSQL Injection Assessment (`nosqli`)

#### Assess Target URL for NoSQL Injection
```bash
dbshield nosqli --url https://app.example.com/items?cat=books
```

#### Assess Nested JSON Request Body
```bash
dbshield nosqli \
  --url https://app.example.com/api/v1/search \
  --method POST \
  --json '{"filter": {"user_id": "100", "role": "member"}, "limit": 10}' \
  --param filter.user_id \
  --format json \
  --output ./nosqli-results.json
```

#### Offline Laboratory Fixture Assessment (Zero Network Traffic)
```bash
dbshield nosqli --fixture ./tests/fixtures/nosqli_sample.json
```

#### NoSQLi Command Options
- `--url`, `-u`: Target URL to assess (required unless `--fixture` is specified).
- `--fixture`: Path to JSON file containing captured baseline and test responses for offline laboratory testing.
- `--param`, `-p`: Specific candidate parameter or nested dot-path to test (e.g. `filter.user_id`).
- `--method`, `-m`: HTTP method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, default `GET`).
- `--data`, `-d`: Raw or URL-encoded form data body.
- `--json`, `-j`: Raw JSON formatted request body (supports nested dictionaries and key paths).
- `--auth-type`: Authentication method (`none`, `bearer`, `basic`, `header`, `cookie`, default `none`).
- `--token`: Bearer authentication token.
- `--username`: HTTP Basic username.
- `--password`: HTTP Basic password.
- `--cookie`: Session cookie string (`session=xyz`).
- `--timeout`: Per-request timeout budget in seconds.
- `--max-budget`: Total request budget ceiling across entire scan (default: 50).
- `--max-param-budget`: Request budget ceiling per candidate parameter (default: 8).
- `--disable-differential`: Disable boolean differential testing (run error-based only).
- `--format`, `-f`: Output format (`text` or `json`, default `text`).
- `--output`, `-o`: File path to export results.
- `--overwrite`: Overwrite destination output file if it exists.

### 6. Centralized Payload Catalog (`payloads`)

Inspect, filter, and validate DBShield's centralized test payload catalog:

#### List All Registered Payloads
```bash
dbshield payloads
```

#### Filter by Engine and Category
```bash
dbshield payloads --engine sqli --category sqli
dbshield payloads --engine nosqli --location json
```

#### Inspect Detailed Payload Specification
```bash
dbshield payloads --info SQLI_ERR_QUOTE
```

#### Validate Catalog Integrity and Pair Relationships
```bash
dbshield payloads --validate
```

#### Export Payload Definitions to JSON
```bash
dbshield payloads --format json --output ./payloads.json --overwrite
```

### 7. Orchestrated Test Execution (`execute`)

Execute controlled security assessment test cases across engines using the Phase 6 execution engine:

#### Run Full Execution Suite on Authorized Target
```bash
dbshield execute --url https://app.example.com/item?id=10
```

#### Targeted Parameter Execution with Custom Budgets
```bash
dbshield execute \
  --url https://app.example.com/search \
  --engine sqli \
  --param q \
  --max-budget 20 \
  --max-param-budget 6
```

#### Offline Laboratory Fixture Assessment (Zero Network Traffic)
```bash
dbshield execute \
  --fixture ./tests/fixtures/sqli_sample.json \
  --engine sqli \
  --format json \
  --output ./execution_run.json
```

#### Execute Command Options
- `--url`, `-u`: Target URL to assess (required unless `--fixture` is specified).
- `--fixture`: Path to JSON file containing captured baseline and test responses.
- `--engine`, `-e`: Target detection engine (`sqli`, `nosqli`, or `all`, default `all`).
- `--param`, `-p`: Specific candidate parameter to test.
- `--method`, `-m`: HTTP request method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`).
- `--data`, `-d`: Raw or form data.
- `--json`, `-j`: JSON request body.
- `--max-budget`: Global request budget ceiling (default: 50).
- `--max-param-budget`: Per-parameter request ceiling (default: 15).
- `--timeout`: HTTP request timeout in seconds.
- `--format`, `-f`: Output format (`text` or `json`, default `text`).
- `--output`, `-o`: File path to export execution run results.
- `--overwrite`: Overwrite destination output file if it exists.

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
| `DBSHIELD_ALLOWED_HOSTS` | List or comma-separated string of authorized hosts | `[]` |
| `DBSHIELD_ALLOW_SUBDOMAINS`| Whether subdomains are in-scope | `false` |
| `DBSHIELD_RATE_LIMIT` | Max requests per second | `10.0` |

---

## Development and Testing

Execute the test suite (291 unit and integration tests):
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
│       ├── phase-01.md       # Phase 1: Project Foundation & Architecture
│       ├── phase-02.md       # Phase 2: Login Page Discovery Engine
│       ├── phase-03.md       # Phase 3: HTTP Request & Session Management
│       ├── phase-04.md       # Phase 4: SQL Injection Testing Engine
│       ├── phase-05.md       # Phase 5: NoSQL Injection Detection Engine
│       └── phase-06.md       # Phase 6: Payload Catalog & Test Execution Engine
├── src/
│   └── dbshield/
│       ├── __init__.py       # Package metadata
│       ├── __main__.py       # Module entry point
│       ├── cli.py            # Typer CLI interface (all commands)
│       ├── config.py         # Pydantic Settings management
│       ├── exceptions.py     # Structured exception hierarchy
│       ├── logging_config.py # Structured logging and secret redaction
│       ├── models/           # Domain data models (Target, Scan, Discovery)
│       ├── scope/            # ScopeManager boundary enforcement
│       ├── http/             # Scope-aware SafeHTTPClient
│       ├── discovery/        # Login Page Discovery Engine
│       ├── auth/             # Session & Authentication Management
│       ├── sqli/             # SQL Injection Detection Engine
│       ├── nosqli/           # NoSQL Injection Detection Engine
│       ├── payloads/         # Centralized Payload Catalog & Models
│       └── execution/        # Orchestrator, Transformers, Policies & Adapters
└── tests/
    ├── unit/                 # Unit tests (config, models, scope, logging, cli, parser, classifier, sqli, nosqli, payloads, execution)
    ├── integration/          # Integration tests (HTTP client, discovery, auth, sqli, nosqli, execution orchestrator, cli)
    └── fixtures/             # Offline laboratory test fixtures
```

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
