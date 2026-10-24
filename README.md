# DBShield

**DBShield** is a professional, modular CLI security framework designed for discovering, analyzing, and testing database-related vulnerabilities (SQL Injection, NoSQL Injection, authentication weaknesses) in web applications.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: Mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](https://mypy-lang.org/)
[![Tests: Pytest](https://img.shields.io/badge/tests-441%20passed-brightgreen.svg)](#)

---

> [!WARNING]
> **Authorized Security Testing Only**: DBShield is engineered solely for authorized security assessments, penetration testing, defensive auditing, and vulnerability research conducted with explicit, written authorization from the target system owner. Unauthorized testing against systems without permission is illegal and strictly prohibited.

---

## Table of Contents

- [Project Status](#project-status)
  - [Implemented Functionality (Phases 1–9)](#implemented-functionality-phases-19)
  - [Planned Features (Phase 10 & Beyond)](#planned-features-phase-10--beyond)
- [Prerequisites](#prerequisites)
- [Installation Guide](#installation-guide)
  - [Windows Installation (PowerShell)](#windows-installation-powershell)
  - [Ubuntu Linux Installation (Bash)](#ubuntu-linux-installation-bash)
  - [WSL2 Ubuntu Installation](#wsl2-ubuntu-installation)
  - [macOS Installation](#macos-installation)
- [Development Setup](#development-setup)
- [Quick Start Guide](#quick-start-guide)
- [Command Reference](#command-reference)
- [Testing and Limitations](#testing-and-limitations)
- [Troubleshooting](#troubleshooting)
- [Security and Responsible Use](#security-and-responsible-use)
- [Configuration Reference](#configuration-reference)
- [Repository Structure](#repository-structure)
- [Documentation & Contribution](#documentation--contribution)
- [License](#license)

---

## Project Status

- **Current Status**: **Phases 1–9 Completed and Verified**
- **Roadmap**: 10 Phases leading to advanced database vulnerability detection and upstream proxy integration. See [docs/roadmap.md](docs/roadmap.md).

### Implemented Functionality (Phases 1–9)

DBShield provides a defense-in-depth security testing framework with 12 CLI commands and verified detection engines:

#### 1. Foundation & Core Architecture (Phase 1)
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

#### 2. Login Page Discovery Engine (Phase 2)
- **Dedicated Discovery Command (`dbshield discover`)**:
  - Validates URL syntax and scope authorization before any network transmission.
  - Safe, minimal page retrieval using the scope-enforcing `SafeHTTPClient`.
  - Tolerant HTML parsing (`HTMLFormParser`) extracting forms, actions, methods, encodings, and control inventories.
  - Resolves relative form actions, strips non-transmittable URL fragments, and defaults missing actions to document URL per HTML standards.
  - Rule-based heuristic classification (`DiscoveryClassifier`) identifying username, email, password, OTP, and anti-CSRF fields.
  - Explanatory page classification (`LOGIN_FORM_DETECTED`, `MULTIPLE_LOGIN_FORMS`, `LOGIN_INPUTS_WITHOUT_FORM`, `NO_LOGIN_FORM_DETECTED`).
  - Action destination boundary validation: detects out-of-scope actions and marks them without sending any requests.
  - Rich human-readable terminal reports and deterministic machine-readable JSON exports (`--format json`, `--output <path>`, `--overwrite`).

#### 3. HTTP Request Handling & Authentication Management (Phase 3)
- **Dedicated Request Command (`dbshield request`)**:
  - Controlled, scope-verified outbound HTTP requests with explicit method configuration (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).
  - Configurable request headers, query parameters, form data, and JSON payloads.
  - Authentication profiles: unauthenticated, Bearer token, HTTP Basic (Base64), custom headers, and session cookies.
  - Target-bound session management (`SessionManager`) ensuring strict origin isolation.
  - Cross-origin redirect credential stripping: sensitive `Authorization` headers and `Cookie` values are scrubbed when redirecting to a different origin.
  - Response memory safety: bounded response bodies with `max_response_size_bytes` and truncation indicators.
  - Case-insensitive response headers (`CaseInsensitiveDict`) and `httpx.Response` duck-typing compatibility (`.text`, `.content`, `.json()`).
  - Strict zero-secret guarantee: passwords, tokens, and cookies are masked as `[REDACTED]` in terminal reports, logs, and JSON exports.

#### 4. SQL Injection Detection Engine (Phase 4)
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

#### 5. NoSQL Injection Detection Engine (Phase 5)
- **Dedicated NoSQLi Command (`dbshield nosqli`)**:
  - Controlled, defensive testing of candidate parameters for NoSQL injection.
  - Recursive nested JSON parameter extraction discovering candidate key paths (e.g. `filter.user_id`).
  - Isolated JSON deep mutation preserving all sibling fields and outer schema structure.
  - Error-based detector (`NoSQLErrorDetector`) with signature catalog for MongoDB (operator rejection, JavaScript `$where`, PyMongo errors, BSON exceptions, Mongoose CastError, regex errors), CouchDB (view compilation, Mango selectors), and generic document stores.
  - MongoDB ObjectId normalization: masks 24-hex-character ObjectIds (`[DYNAMIC_OBJECTID]`) to prevent artificial divergence in similarity calculations.
  - Operator and boolean differential detector (`NoSQLDifferentialDetector`) evaluating paired truthy/falsy queries.
  - Offline response fixture analysis (`--fixture <path>`): zero-network laboratory validation from captured JSON fixtures.
  - Safety firewall: sensitive parameters (`password`, `token`, `csrf`, `secret`, `otp`) are automatically skipped.

#### 6. Payload Catalog & Test Execution Orchestration (Phase 6)
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

#### 7. Evidence Analysis & Vulnerability Verification (Phase 7)
- **Normalized Evidence & Provenance Model (`NormalizedEvidence`, `EvidenceProvenance`)**:
  - Standardized representations capturing error signatures, differential pairs, status differences, similarity metrics, and execution traces.
  - Full provenance tracking linking evidence to target endpoints, parameters, transport locations, test IDs, payload IDs, and execution runs.
  - Automated credential scrubbing: sensitive parameters (`password`, `token`, etc.), authorization headers, bearer tokens, cookies, JWTs, and API keys are redacted from snippets and parameter names.
- **Deterministic Correlation & Deduplication (`EvidenceCorrelator`)**:
  - Groups evidence by canonical target URL, vulnerability class, transport location, and parameter name while preserving distinct findings.
  - Eliminates duplicate observations across repeated runs while preserving execution references and logging audit notes.
- **Explainable Confidence Assessor (`ConfidenceAssessor`)**:
  - Multi-factor scoring (0.0 to 1.0) with separate observation confidence and vulnerability confidence.
  - Calibrated rubric evaluating database error specificity (MySQL, PostgreSQL, MongoDB, SQLite vs generic), baseline stability, differential divergence, and detector agreement.
- **Formal Verification State Machine (`VerificationStateMachine`)**:
  - Explicit 8-state finding lifecycle (`POTENTIAL_INDICATOR`, `UNDER_ANALYSIS`, `VERIFICATION_REQUIRED`, `CORROBORATED`, `VERIFIED`, `INCONCLUSIVE`, `REJECTED`, `UNVERIFIABLE`).
  - Strict domain prerequisites: failed executions, pre-existing baseline errors, unstable baselines, or generic server errors are prevented from confirming vulnerabilities.
  - Enforces valid transition graphs and maintains an immutable transition audit trail.
- **Evidence-Based False-Positive Elimination**:
  - Automatically identifies and rejects pre-existing baseline database faults, generic HTTP 400/500 errors, unstable baselines, and contradictory responses.
- **Dedicated CLI Command (`dbshield verify`)**:
  - Comprehensive verification interface supporting offline execution run results (`--input`), response fixtures (`--fixture`), and live scope-checked scans (`--url`).

#### 8. Structured Results, Finding Normalization & Professional Reporting (Phase 8)
- **Normalized Finding Model (`NormalizedSecurityFinding`, `SecurityAssessmentReport`)**:
  - Unified finding representation with deterministic SHA-256 IDs (`DBS-<HEX>`), endpoint path, transport location, redacted parameters, verification status, and confidence score.
  - Decoupled qualitative severity rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) ensuring unverified indicators are never exaggerated.
  - Direct Common Weakness Enumeration association (`CWE-89` for SQLi, `CWE-943` for NoSQLi) and actionable remediation guidance.
- **Finding Normalizer & Deduplication (`FindingNormalizer`)**:
  - Converts results from verification, SQLi, NoSQLi, and execution engines into canonical findings.
  - Standardizes endpoint paths and groups identical observations deterministically, promoting the highest verification status and accumulating corroborating evidence counts.
- **Multi-Format Export Subsystem (`dbshield.reporting.exporters`)**:
  - `JSONReportExporter`: Valid JSON with schema version `1.0.0` and summary envelopes.
  - `CSVReportExporter`: RFC-4180 compliant tabular export with formula injection protection.
  - `MarkdownReportExporter`: Executive summary, metrics tables, and detailed technical findings in GitHub-flavored Markdown.
  - `TerminalReportExporter`: Formatted terminal output adhering to `linux-cli-design-system` standards with `NO_COLOR` support.
- **Centralized Redaction & CSV Formula Injection Protection**:
  - Scrubbing authorization headers, tokens, cookies, database credentials, connection strings, JWTs, and API keys.
  - Neutralizes dangerous spreadsheet formula characters (`=`, `+`, `-`, `@`, `\t`, `\r`) in CSV cells by prepending single quotes.
- **Dedicated CLI Command (`dbshield report`)**:
  - Multi-format report generation supporting input file ingestion (`--input`), format selection (`--format`), minimum severity filtering (`--severity`), status filtering (`--status`), output file writing (`--output`), and overwrite protection (`--overwrite`).

#### 9. Laboratory Validation, Detection Reliability & Stabilization (Phase 9)
- **Deterministic Offline Validation Framework (`LabValidationRunner`)**:
  - Offline evaluation engine executing simulated HTTP requests via `respx` mock routing without external network transmissions.
  - Dynamic pattern matching prioritizing probe patterns and payloads before baseline fallback routes.
- **Canonical 20-Scenario Benchmark Catalog (`load_standard_scenarios`)**:
  - 13 SQL injection scenarios (MySQL, PostgreSQL, SQLite, MSSQL, Oracle error-based and boolean differential).
  - 6 NoSQL injection scenarios (MongoDB, CouchDB error-based and operator differential).
  - Safety guardrail scenarios (credential parameter skipping, scope boundary enforcement).
  - Explicit coverage of known-positive, known-negative, and ambiguous edge cases.
- **Confusion Matrix & Accuracy Evaluation (`ConfusionMatrix`)**:
  - Transparent statistical tracking of True Positives, False Positives, True Negatives, False Negatives, Inconclusive, and Skipped outcomes.
  - Precision, Recall, F1 score, and Accuracy calculations with documented dataset limitations.
- **Performance & Resource Profiler (`PerformanceProfiler`)**:
  - Microbenchmarking suite measuring latency, ops/sec throughput, and peak memory allocations across payload generation, signature scanning, boolean differential comparisons, finding correlation, and report exports.
- **Dedicated CLI Command (`dbshield validate`)**:
  - Offline scenario execution with suite filtering (`--suite`), tag filtering (`--tag`), format selection (`--format terminal|json`), file export (`--output`), and profiling (`--profile`).

### Planned Features (Phase 10 & Beyond)

The following capabilities are explicitly **planned for Phase 10** or subsequent development cycles and are **not yet implemented**:

- **Burp Suite Extension Integration (Phase 10)**: PortSwigger Montoya API bindings, passive traffic observation via Burp proxy, context-menu assessment triggers, and Burp issue activity reporting.
- **Active Exploitation & Data Dumping**: DBShield does *not* extract database schemas, dump table contents, or crack password hashes.
- **Full-Site Web Crawling**: DBShield tests explicit URLs and forms provided by the user; it does not crawl entire web applications.
- **Arbitrary Proxy Interception**: Standalone HTTP/S interception proxying is planned for integration in Phase 10.

---

## Prerequisites

Before installing DBShield, verify that your system satisfies the following baseline requirements:

| Component | Minimum Requirement | Notes |
| :--- | :--- | :--- |
| **Python** | **3.12.0 or newer** | Strict constraint (`requires-python = ">=3.12"`). Python 3.10 and 3.11 are **not supported**. |
| **Git** | 2.20 or newer | Required for cloning the repository and managing version control. |
| **Virtual Environment** | `venv` module | Strongly recommended to prevent dependency conflicts with system packages. |
| **Operating System** | Windows 10/11, Ubuntu 22.04/24.04, WSL2, or macOS 12+ | Cross-platform pure Python architecture without compiled binary requirements. |

### Operating System Support Matrix

| Platform | Verification Status | Primary Shell | Notes |
| :--- | :--- | :--- | :--- |
| **Windows 11 / 10** | **Directly Verified** in local environment | PowerShell 5.1 / 7+ | Execution-policy scoping required for `Activate.ps1`. |
| **Ubuntu 24.04 LTS** | Verified via configuration & dependencies | Bash / Zsh | Ships with Python 3.12 by default (`python3-venv`). |
| **Ubuntu 22.04 LTS** | Verified via configuration & dependencies | Bash / Zsh | Ships with Python 3.10; requires Python 3.12 via deadsnakes PPA. |
| **WSL2 (Ubuntu on Windows)** | Verified via architecture & design standards | Bash | Supports both native ext4 checkouts and `/mnt/<drive>/...` mounts. |
| **macOS (Apple Silicon & Intel)** | Verified via package metadata & dependency inspection | Zsh / Bash | Pure Python libraries; installed via Homebrew `python@3.12`. |

---

## Installation Guide

### Windows Installation (PowerShell)

Follow these step-by-step instructions in Windows PowerShell (or PowerShell 7+):

#### 1. Verify Prerequisites
Open PowerShell and verify Python and Git:
```powershell
python --version
git --version
```
> [!NOTE]
> The Python version output must be `Python 3.12.x` or higher. If `python` points to an older version or opens the Windows Store, install Python 3.12 from [python.org](https://www.python.org/downloads/) and ensure **"Add python.exe to PATH"** is checked.

#### 2. Obtain the Repository

**Option A: Fresh Clone from GitHub**
```powershell
git clone https://github.com/Amirbarkhordari/DBShield.git
cd DBShield
```

**Option B: Enter an Existing Local Checkout**
```powershell
cd "D:\path\to\DBShield"
```
*(Replace `"D:\path\to\DBShield"` with the actual path to your repository).*

#### 3. Create and Activate a Virtual Environment
Create an isolated Python environment:
```powershell
python -m venv .venv
```

Activate the environment:
```powershell
.\.venv\Scripts\Activate.ps1
```

> [!IMPORTANT]
> **PowerShell Execution Policy Handling**:
> If you encounter the error:
> ```text
> File ...\.venv\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled on this system.
> ```
> **Do not make dangerous machine-wide security changes.** Instead, permit script execution **only for the current PowerShell process**:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .\.venv\Scripts\Activate.ps1
> ```
> This command safely permits activation for your current terminal window without altering system-wide or user-wide registry policies. Alternatively, you can use the Command Prompt (`cmd.exe`) activation script: `.\.venv\Scripts\activate.bat`.

#### 4. Install Project and Dependencies
Upgrade `pip` and install DBShield in editable development mode:

**Core Package Only:**
```powershell
python -m pip install --upgrade pip
pip install -e .
```

**Full Package with Development & Test Suite (Recommended):**
```powershell
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

#### 5. Verify CLI Functionality
Verify that the entry point is active and healthy:
```powershell
dbshield --version
dbshield doctor
```
Expected output:
```text
[*] Running DBShield environment and system readiness diagnostics...
[+] Python Runtime: 3.12.x (>= 3.12 required - OK)
[+] Configuration: Valid (Log level: INFO, Timeout: 10.0s)
[+] Workspace Directory: ... (Writable - OK)
[+] All diagnostic checks passed. DBShield environment is ready.
```

---

### Ubuntu Linux Installation (Bash)

Follow these sequential instructions on Ubuntu / Debian systems:

#### 1. Install System Prerequisites

**On Ubuntu 24.04 LTS (Noble Numbat):**
Ubuntu 24.04 includes Python 3.12 in the base repositories:
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

**On Ubuntu 22.04 LTS (Jammy Jellyfish):**
Ubuntu 22.04 defaults to Python 3.10. Install Python 3.12 from the official Deadsnakes PPA:
```bash
sudo apt update
sudo apt install -y software-properties-common git
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3.12-dev python3-pip
```

#### 2. Clone or Enter the Repository
```bash
git clone https://github.com/Amirbarkhordari/DBShield.git
cd DBShield
```

#### 3. Create and Activate Virtual Environment
```bash
python3.12 -m venv .venv
source .venv/bin/activate
```
*(On Ubuntu 24.04, `python3 -m venv .venv` can be used directly).*

#### 4. Install Dependencies
```bash
pip install --upgrade pip
pip install -e ".[dev]"
```

#### 5. Verify CLI Functionality
```bash
dbshield --version
dbshield doctor
```

---

### WSL2 Ubuntu Installation

WSL2 (Windows Subsystem for Linux) provides a native Linux environment inside Windows. You can run DBShield either from a Windows-mounted path or within the native Linux filesystem.

#### 1. Verify WSL2 and Ubuntu Status
In Windows PowerShell, check your WSL status:
```powershell
wsl --status
wsl -l -v
```
Launch your Ubuntu distribution:
```powershell
wsl -d Ubuntu
```

#### 2. Choose Your Repository Location

There are two primary ways to run DBShield in WSL2:

##### Approach A: Accessing an Existing Windows Checkout (`/mnt/<drive>/...`)
If your project checkout is located on a Windows drive (e.g., `D:\Project-self\new project`), access it via the `/mnt/` mount:
```bash
# Handle paths containing spaces with double quotes:
cd "/mnt/d/Project-self/new project"
```

> [!WARNING]
> **Virtual Environment Isolation**:
> **Never share a `.venv` directory between Windows and WSL2.** Windows uses PE binaries (`.venv/Scripts/python.exe`), while WSL2 requires Linux ELF binaries (`.venv/bin/python`).
>
> If a `.venv` already exists for Windows in that directory, create a dedicated Linux virtual environment:
> ```bash
> python3.12 -m venv .venv-wsl
> source .venv-wsl/bin/activate
> pip install --upgrade pip
> pip install -e ".[dev]"
> ```

##### Approach B: Cloning Directly into the Linux Filesystem (Recommended for I/O Speed)
For optimal performance, clone the repository into your WSL2 home directory (`ext4` filesystem):
```bash
mkdir -p ~/projects
cd ~/projects
git clone https://github.com/Amirbarkhordari/DBShield.git
cd DBShield
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

#### 3. Practical Trade-offs: Windows Mount vs. Native Linux Filesystem

| Dimension | Windows Mount (`/mnt/<drive>/...`) | Native Linux Filesystem (`~/...`) |
| :--- | :--- | :--- |
| **I/O Performance** | Slower (Plan 9 / 9P filesystem bridge between OS layers). | **Fastest** (Native Linux `ext4` disk image). |
| **Test Suite Speed** | 441 tests take ~60–80 seconds due to cross-boundary I/O. | 441 tests take ~30–45 seconds. |
| **File Watching (`inotify`)** | Can suffer from delayed change notifications. | Instantaneous kernel-level `inotify` events. |
| **Line Endings** | Windows checkout may contain `CRLF` (requires `.gitattributes`). | Native `LF` line endings preserved. |
| **IDE Integration** | Direct file editing from Windows IDEs (e.g., Visual Studio). | Accessible via VS Code Remote-WSL or `\\wsl$\Ubuntu\home\...`. |

#### 4. Verify CLI in WSL2
```bash
dbshield --version
dbshield doctor
```

---

### macOS Installation

DBShield supports macOS 12 (Monterey), 13 (Ventura), 14 (Sonoma), and 15 (Sequoia) across both Apple Silicon (M1/M2/M3/M4) and Intel x86_64 architectures.

> [!NOTE]
> **Support Evidence**: DBShield is an entirely pure-Python package relying on universal libraries (`typer`, `pydantic`, `httpx`, `rich`, `beautifulsoup4`). No platform-specific native C compilation or OS-specific syscalls are required.

#### 1. Install Prerequisites via Homebrew
If you do not have Homebrew installed, follow the instructions at [brew.sh](https://brew.sh). Then install Python 3.12 and Git:
```bash
brew update
brew install python@3.12 git
```

#### 2. Clone and Setup
```bash
git clone https://github.com/Amirbarkhordari/DBShield.git
cd DBShield
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

#### 3. Verify CLI Functionality
```bash
dbshield --version
dbshield doctor
```

---

## Development Setup

If you are contributing to DBShield or running quality checks, install the development dependencies:

```bash
pip install -e ".[dev]"
```

### Running Quality Checks & Tests

Execute the following commands to validate code quality, formatting, typing, and test passing:

```bash
# 1. Run the complete test suite (unit and integration tests)
pytest

# 2. Run concise test execution
python -m pytest tests -q

# 3. Collect and verify statement coverage
pytest --cov=dbshield --cov-report=term-missing

# 4. Perform linting checks with Ruff
ruff check src tests

# 5. Automatically fix safe lint issues
ruff check --fix src tests

# 6. Verify code formatting style with Ruff
ruff format --check src tests

# 7. Apply automatic code formatting
ruff format src tests

# 8. Perform static type analysis with Mypy
mypy src

# 9. Verify Git whitespace and formatting diff
git diff --check
```

---

## Quick Start Guide

Once DBShield is installed and your virtual environment is activated, you can explore its capabilities:

### 1. View Top-Level CLI Help
Display all available commands and global options:
```bash
dbshield --help
```

### 2. Verify Environment Diagnostics
Verify Python runtime, configuration, and writable workspace access:
```bash
dbshield doctor
```

### 3. Passive Target Inspection (Zero Network Traffic)
Inspect a target URL syntax and scope authorization rules without transmitting any network packets:
```bash
dbshield inspect --url "https://app.example.com/login?redirect=dashboard"
```

### 4. Run Built-In Offline Laboratory Validation
DBShield includes an offline validation suite containing 20 canonical positive, negative, and ambiguous injection scenarios using simulated HTTP responses:

```bash
# View all validation options:
dbshield validate --help

# Run the complete 20-scenario offline validation benchmark:
dbshield validate --suite all

# Run validation with performance profiling and microbenchmarks:
dbshield validate --profile

# Run only SQL injection scenarios tagged with 'error':
dbshield validate --suite sqli --tag error
```

**Expected Outcome**:
The command executes in ~1–2 seconds, reporting verdicts for each scenario, confusion matrix metrics (TP, FP, TN, FN, Precision, Recall, F1, Accuracy), and dataset limitation disclosures.

### 5. Multi-Format Assessment Reporting
Generate structured security reports from scan findings or verification result files:

```bash
# View report options:
dbshield report --help

# Generate a formatted terminal report from finding data:
dbshield report --input ./tests/fixtures/sqli_sample.json --format text

# Export findings to GitHub-Flavored Markdown:
dbshield report --input ./tests/fixtures/sqli_sample.json --format markdown --output assessment.md --overwrite

# Export findings to formula-safe CSV:
dbshield report --input ./tests/fixtures/sqli_sample.json --format csv --output findings.csv --overwrite
```

---

## Command Reference

| Command | Purpose | Network Calls | Key Options |
| :--- | :--- | :---: | :--- |
| `dbshield doctor` | Diagnostic readiness verification | None | None |
| `dbshield info` | Active configuration summary | None | None |
| `dbshield inspect` | Passive URL syntax & scope evaluation | None | `--url`, `-u` |
| `dbshield discover` | Login page & form discovery | Authorized Target | `--url`, `--format`, `--output`, `--overwrite` |
| `dbshield request` | Scope-verified HTTP request dispatch | Authorized Target | `--url`, `--method`, `--auth-type`, `--header`, `--json` |
| `dbshield sqli` | SQL injection detection | Target / Fixture | `--url`, `--fixture`, `--param`, `--format`, `--max-budget` |
| `dbshield nosqli` | NoSQL injection detection | Target / Fixture | `--url`, `--fixture`, `--param`, `--format`, `--max-budget` |
| `dbshield payloads` | Centralized payload catalog inspection | None | `--engine`, `--category`, `--info`, `--validate` |
| `dbshield execute` | Multi-engine orchestrated execution | Target / Fixture | `--url`, `--fixture`, `--engine`, `--param`, `--max-budget` |
| `dbshield verify` | Evidence analysis & false-positive elimination | None (offline mode) | `--input`, `--fixture`, `--url`, `--format`, `--output` |
| `dbshield report` | Multi-format reporting (JSON, CSV, MD, Text) | None | `--input`, `--format`, `--severity`, `--status`, `--output` |
| `dbshield validate` | Phase 9 offline benchmark & profiler | None (mock HTTP) | `--suite`, `--tag`, `--format`, `--output`, `--profile` |

---

## Testing and Limitations

### Testing Methodology Tiers

DBShield utilizes four distinct tiers of testing to ensure detection reliability and software stability:

1. **Unit Tests (441 Tests)**:
   - Verify isolated components: Pydantic models, URL normalization, HTML form parsing, heuristic classifiers, SQL/NoSQL signature matching, payload mutation logic, confidence scoring algorithms, and report exporters.
   - Run purely in memory without network or external system dependencies.

2. **Integration Tests**:
   - Verify end-to-end interactions between subsystems: CLI command dispatch, session managers, execution orchestrator lifecycle, and reporter formatting pipelines.

3. **Deterministic Synthetic Validation Scenarios (`dbshield validate`)**:
   - 20 authored scenarios running against simulated `respx` mock HTTP routers.
   - Purpose: Prove that the detection engines correctly identify canonical database error signatures, boolean differential variations, clean queries, generic 500 errors, pre-existing errors, and safety boundary exclusions.

4. **Live Authorized Target Assessments**:
   - Controlled security testing against authorized live web applications under explicit written scope agreements.

### Limitations and Operational Realities

> [!IMPORTANT]
> **Synthetic Benchmarks Do Not Guarantee Real-World Exploitability**:
> - The 100% precision, recall, and accuracy metrics reported by `dbshield validate` apply strictly to the authored 20-scenario benchmark dataset.
> - **Real-world applications are non-deterministic**: Production targets introduce Web Application Firewalls (Cloudflare, AWS WAF, ModSecurity), dynamic single-page application rendering, asynchronous backend queues, rate limiters, custom character encodings, and non-standard SQL dialects.
> - A finding classified as `POTENTIAL_INDICATOR` indicates evidence of abnormal behavior that requires analyst verification; it does not constitute proof of active exploitability.
> - Conversely, `NO_INDICATOR` indicates that candidate payloads did not produce differential or error signals; it does not prove the target is vulnerability-free.

---

## Troubleshooting

### 1. Python Version Mismatch
- **Symptom**: `SyntaxError: unsupported operand type(s) for |: 'type' and 'type'` or `Python 3.12+ required`.
- **Cause**: An older Python version (e.g., Python 3.10 or 3.11) is executing DBShield.
- **Resolution**:
  - Run `python --version` to verify the active interpreter.
  - On Ubuntu, install Python 3.12 via deadsnakes PPA: `sudo apt install python3.12 python3.12-venv`.
  - Recreate your virtual environment with `python3.12 -m venv .venv`.

### 2. PowerShell Script Execution Disabled
- **Symptom**:
  ```text
  File ...\Activate.ps1 cannot be loaded because running scripts is disabled on this system.
  ```
- **Cause**: PowerShell's default `Restricted` execution policy blocks unauthenticated script execution.
- **Resolution**:
  - Execute: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
  - Re-run: `.\.venv\Scripts\Activate.ps1`
  - This affects only your current terminal session and does not compromise system security.

### 3. Cross-OS Virtual Environment Conflicts (WSL2 / Windows)
- **Symptom**:
  ```text
  bash: .venv/bin/activate: No such file or directory
  ```
  or `cannot execute binary file: Exec format error`.
- **Cause**: Attempting to activate a Windows-created `.venv` (which contains `.exe` binaries) inside WSL2 Linux, or vice versa.
- **Resolution**:
  - Do not share virtual environments across the Windows/Linux boundary.
  - In WSL2, create a Linux-specific virtual environment: `python3.12 -m venv .venv-wsl`.

### 4. Paths Containing Spaces
- **Symptom**: `cd: too many arguments` or `FileNotFoundError` when navigating to checkout paths like `D:\Project-self\new project`.
- **Cause**: Unquoted whitespace in shell arguments.
- **Resolution**:
  - Always quote paths in PowerShell: `cd "D:\Project-self\new project"`
  - Always quote paths in Bash/WSL: `cd "/mnt/d/Project-self/new project"`

### 5. Missing Development Dependencies
- **Symptom**: `ModuleNotFoundError: No module named 'pytest'` or `ruff`.
- **Cause**: Project was installed using `pip install -e .` without the `[dev]` extras group.
- **Resolution**:
  - Install development tools: `pip install -e ".[dev]"`.

### 6. Target Parameter Marked as `SKIPPED`
- **Symptom**: When running `dbshield sqli` or `dbshield nosqli`, candidate parameters named `password`, `token`, or `csrf` are skipped.
- **Cause**: DBShield includes an intentional safety guardrail preventing automated mutation of authentication and session tokens to avoid account lockouts.
- **Resolution**: This is expected behavior. If you need to test authentication flows, use `dbshield request` or explicit parameter targeting with `--param`.

---

## Security and Responsible Use

### 1. Authorization and Scope Requirements
- DBShield must only be executed against systems that you own or for which you have received **explicit, written authorization** from the system owner.
- Always configure `DBSHIELD_ALLOWED_HOSTS` or pass verified target URLs to prevent inadvertent out-of-scope network transmissions.
- Target redirection boundaries are strictly enforced: if a target redirects to an out-of-scope host, `SafeHTTPClient` halts requests immediately.

### 2. Offline Validation Boundaries
- The Phase 9 validation suite (`dbshield validate`) operates **strictly in memory** using `respx` mock HTTP routers.
- It generates **zero external network traffic**, sends no packets to public networks, and requires no internet connection.

### 3. Sensitive Data Redaction
- DBShield automatically scrubs sensitive parameters (`password`, `token`, `secret`, `api_key`, `session`), HTTP `Authorization` headers, cookies, and database connection strings from terminal outputs, log files, and exported reports.
- **Risk of Disabling Redaction (`--no-redact`)**:
  - The CLI provides a `--no-redact` option for debugging in strictly isolated environments.
  - **Warning**: Using `--no-redact` exposes plain-text credentials in logs and terminal streams. Never use `--no-redact` in production, shared workstations, or environments where logs are forwarded to centralized SIEM systems.

### 4. CSV Formula Injection (DDE) Neutralization
- When exporting assessment findings to CSV (`dbshield report --format csv`), untrusted cell values beginning with formula operators (`=`, `+`, `-`, `@`, `\t`, `\r`) are automatically escaped with a leading single quote (`'`). This prevents automatic macro execution when opening reports in spreadsheet applications such as Microsoft Excel or LibreOffice Calc.

---

## Configuration Reference

Configuration can be specified via environment variables or a local `.env` file (see `.env.example`):

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DBSHIELD_HTTP_TIMEOUT` | Request timeout in seconds | `10.0` |
| `DBSHIELD_MAX_REDIRECTS` | Maximum redirects to follow | `5` |
| `DBSHIELD_USER_AGENT` | HTTP User-Agent header string | `DBShield/0.1.0 (Defensive Testing Framework)` |
| `DBSHIELD_LOG_LEVEL` | Log severity level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `INFO` |
| `DBSHIELD_LOG_FILE` | Optional path to write persistent log output | `None` |
| `DBSHIELD_DATA_DIR` | Cache and session storage directory | `~/.local/share/dbshield` |
| `DBSHIELD_ALLOWED_HOSTS` | List or comma-separated string of authorized hosts | `[]` |
| `DBSHIELD_ALLOW_SUBDOMAINS`| Whether subdomains of allowed hosts are in-scope | `false` |
| `DBSHIELD_RATE_LIMIT` | Maximum requests per second ceiling | `10.0` |

---

## Repository Structure

```text
dbshield/
├── README.md                 # Project overview and cross-platform installation guide
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
│       ├── phase-06.md       # Phase 6: Payload Catalog & Test Execution Engine
│       ├── phase-07.md       # Phase 7: Evidence Analysis & Vulnerability Verification
│       ├── phase-08.md       # Phase 8: Structured Results, Finding Normalization & Professional Reporting
│       └── phase-09.md       # Phase 9: Lab Validation, Detection Reliability & Stabilization
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
│       ├── execution/        # Orchestrator, Transformers, Policies & Adapters
│       ├── verification/     # Evidence Normalizer, Correlator, Confidence & Verification Engine
│       ├── reporting/        # Finding Models, Severity Assessor, Exporters (JSON, CSV, MD, Terminal)
│       └── validation/       # Offline Lab Runner, Benchmark Scenarios, Profiler & Metrics
└── tests/
    ├── unit/                 # Unit tests (models, scope, logging, cli, sqli, nosqli, payloads, etc.)
    ├── integration/          # Integration tests (HTTP client, discovery, execution, verify, report, validate)
    └── fixtures/             # Offline laboratory test fixtures
```

---

## Documentation & Contribution

For technical architecture, design patterns, and contributor guidelines, refer to the project documentation:

- **System Architecture**: [docs/architecture.md](docs/architecture.md)
- **10-Phase Roadmap**: [docs/roadmap.md](docs/roadmap.md)
- **Contributor Guidelines**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Development Workflow**: [docs/development.md](docs/development.md)
- **Changelog History**: [CHANGELOG.md](CHANGELOG.md)
- **Phase 8 Specification (Reporting)**: [docs/phases/phase-08.md](docs/phases/phase-08.md)
- **Phase 9 Specification (Validation)**: [docs/phases/phase-09.md](docs/phases/phase-09.md)
- **Phase Specifications (1–9)**: [docs/phases/phase-01.md](docs/phases/phase-01.md), [phase-02.md](docs/phases/phase-02.md), [phase-03.md](docs/phases/phase-03.md), [phase-04.md](docs/phases/phase-04.md), [phase-05.md](docs/phases/phase-05.md), [phase-06.md](docs/phases/phase-06.md), [phase-07.md](docs/phases/phase-07.md), [phase-08.md](docs/phases/phase-08.md), [phase-09.md](docs/phases/phase-09.md)

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
