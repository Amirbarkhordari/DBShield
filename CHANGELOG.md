# Changelog

All notable changes to the **DBShield** framework are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-10-22

### Added
- **Phase 4 SQL Injection Detection Engine**: Initial defensive assessment engine for detecting database syntax errors and differential response signals.
- **CLI SQLi Command (`dbshield sqli`)**: CLI entry point supporting target URLs, candidate parameter filtering, request budgets, authentication injection, JSON export, and offline fixture assessment.
- **Offline Response Fixture Analysis**: Support for `--fixture <path>` enabling deterministic, zero-network laboratory validation from recorded JSON response fixtures.
- **Baseline Response Characterization (`BaselineCharacterizer`)**: Profiles normal endpoint status, headers, body length, and elapsed time across multiple sample probes; flags status code variations or content drift as `INCONCLUSIVE`.
- **Database Error Signature Catalog (`SignatureCatalog`)**: Compiled regular expressions detecting syntax errors across 6 database families (MySQL/MariaDB, PostgreSQL, SQLite, Microsoft SQL Server, Oracle, and Generic ANSI SQL).
- **Generic Server Error Differentiation**: Distinguishes database-specific error indicators from generic HTTP 500 / 400 server failure responses (rejecting generic 500s as SQLi proof).
- **Pre-Existing Error Filtering**: Discards error signatures that were already present in baseline responses, preventing false positives from pre-existing backend faults.
- **Dynamic Element Normalization (`ResponseNormalizer`)**: Deterministically masks volatile dynamic elements (ISO/RFC timestamps, UUIDs, CSRF tokens, epochs) and computes structural similarity with `SequenceMatcher`.
- **Boolean Differential Detector (`DifferentialDetector`)**: Compares paired logical condition responses against baseline; flags candidate findings when True condition matches baseline and False condition diverged.
- **Candidate Parameter Metadata**: Tracks parameter name, location (query, body_urlencoded, body_json), method, content-type, eligibility, and skip reasons.
- **Safety Firewall**: Sensitive controls (passwords, tokens, nonces, session identifiers) are automatically flagged ineligible and skipped.
- **Structured Finding Models**: Pydantic models distinguishing `POTENTIAL_INDICATOR`, `NO_INDICATOR`, `INCONCLUSIVE`, `SKIPPED`, `BLOCKED_BY_SCOPE`, and `ERROR`.
- **Signature Span Deduplication**: Interval-based span matching prevents redundant evidence records when signatures overlap on a single error while preserving distinct error occurrences.
- **End-to-End POST Body Testing**: Validated URL-encoded form data and JSON body parameter testing with simulated endpoints.
- **Expanded Test Suite**: Added 70 new unit and integration tests (185 total tests passing 100%, 0 lint errors).

### Security
- **Defensive Assessment Only**: Strictly prohibits database extraction, table dumping, data modification, automated exploitation, or denial-of-service timing queries.
- **Zero-Credential Testing**: Passwords, auth tokens, and session nonces are excluded from test input delivery.
- **Snippet Secret Redaction**: Response snippets captured in evidence records automatically redact passwords, API tokens, and session cookies.
- **Request Budget Ceilings**: Strict per-parameter (`max_param_budget`) and per-scan (`max_budget`) ceilings prevent resource exhaustion.

## [0.3.0] - 2026-10-22

### Added
- **Phase 3 HTTP Request Handling and Authentication Management**: Reliable, reusable HTTP request layer, origin-isolated session management, and credential injection.
- **CLI Request Command (`dbshield request`)**: Safe, scope-verified HTTP execution supporting methods, headers, payloads, authentication profiles, output export, and Linux CLI Design System exit codes.
- **Extended HTTP Client (`SafeHTTPClient`)**: Explicit convenience methods (`get`, `post`, `put`, `patch`, `delete`, `head`, `options`), configurable `max_response_size_bytes` bounding, and session manager integration.
- **HTTP Response Abstraction (`HTTPResponse`)**: Bounded response bodies, case-insensitive headers via `CaseInsensitiveDict`, status classification properties, and `httpx.Response` duck-typing compatibility (`.text`, `.content`, `.json()`).
- **Authentication Configuration (`AuthConfig`)**: Explicit credential profiles for Bearer tokens, HTTP Basic authentication (Base64 encoding), custom headers, and explicit session cookies.
- **Session & Origin Isolation (`SessionManager`)**: Origin-binding to prevent cross-origin credential transmission, automatic cookie jar persistence via `Set-Cookie` ingestion, and explicit session reset/invalidation lifecycles.
- **Cross-Origin Redirect Protection**: Automatically strips `Authorization` headers and cookies when following in-scope redirects to different origins.
- **Conservative Auth State Evaluation**: Distinguishes transport failures from HTTP error responses; preserves the difference between unknown authentication states and confirmed failures (never infers authentication from HTTP 200 alone).
- **Expanded Test Suite**: Added 38 new unit and integration tests (115 total tests passing 100%).

### Security
- **Strict Origin Credential Isolation**: Refuses to transmit session credentials to cross-origin destinations and strips sensitive headers across redirect origins.
- **Zero-Secret Exposure**: Credentials (passwords, tokens, cookies) are masked with `[REDACTED]` in logs, terminal reports, and JSON exports.
- **Response Memory Safety**: Large responses are capped at `max_response_size_bytes` with truncation indicators to prevent out-of-memory denial of service.

## [0.2.0] - 2026-10-22

### Added
- **Phase 2 Login Page Discovery Engine**: Complete login-page discovery, HTML form parsing, and heuristic input classification engine.
- **CLI Discovery Command**: Added `dbshield discover` supporting `--url`, `--format` (`text`, `json`), `--output`, `--overwrite`, and `--timeout` flags.
- **Tolerant HTML Form Parser**: `HTMLFormParser` with BeautifulSoup (`html.parser`) handling forms, actions, methods, encodings, labels, and orphan controls.
- **Relative Action Normalization**: Resolves relative form actions, defaults missing actions to the current document URL, and strips non-transmittable URL fragments (`#...`).
- **Rule-Based Heuristic Classifier**: `DiscoveryClassifier` for categorizing inputs into `USERNAME`, `EMAIL`, `PASSWORD`, `OTP`, `CSRF_TOKEN`, and `HIDDEN` with transparent confidence scoring and evidence trails.
- **Explainable Page Classification**: Evaluates candidate forms and orphan controls to determine `LOGIN_FORM_DETECTED`, `MULTIPLE_LOGIN_FORMS`, `LOGIN_INPUTS_WITHOUT_FORM`, or `NO_LOGIN_FORM_DETECTED`.
- **Action Scope Boundary Protection**: Validates form actions against `ScopeManager` to mark `is_action_in_scope` without dispatching requests to action destinations.
- **Discovery Result Models**: Validated immutable Pydantic models: `DiscoveryResult`, `DiscoveredForm`, `InputField`, `DiscoverySummary`.
- **Lenient Configuration List Parsing**: `LenientEnvSettingsSource` supporting both comma-separated strings and JSON arrays for `allowed_hosts`.
- **Expanded Test Suite**: Added 32 new unit and integration tests (77 total tests passing 100%).

### Security
- **Strict Zero-Credential Guarantee**: Never collects or stores real credentials, passwords, session secrets, or tokens.
- **Zero Active Form Submission**: Operates strictly passively on the retrieved page content without submitting forms or testing passwords.
- **Zero SQLi/NoSQLi Payloads**: Guaranteed complete isolation from active payload execution.

## [0.1.0] - 2026-10-22

### Added
- **Phase 1 Foundation & Architecture**: Complete initial framework baseline.
- **Typer CLI Interface**: Installable `dbshield` binary supporting `--version`, `--help`, `doctor`, `inspect`, and `info`.
- **Target Scope Manager**: Host normalization, strict allowlisting, subdomain boundaries, and redirect validation guards (`ScopeManager`).
- **Scope-Aware HTTP Client**: `SafeHTTPClient` built on `httpx` with timeout budgets, hop limits, and pre-request scope enforcement.
- **Foundational Data Models**: Validated `Target` and `Scan` models with normalization, URL parsing, and scan lifecycle tracking.
- **Centralized Configuration**: `pydantic-settings` management with environment overrides and safe settings exposure (`get_safe_dict`).
- **Structured Exception Hierarchy**: Root `DBShieldError` with 3-part diagnostic details (message, cause, remedy) and specialized subclasses.
- **Logging & Redaction**: Centralized logging filter (`SensitiveDataFilter`) automatically masking passwords, API tokens, JWTs, and cookies.
- **Automated Test Suite**: 45 unit and integration tests covering all Phase 1 components with 100% pass rate.
- **Project Documentation**: Initial architectural specifications, roadmap, development guides, and Phase 1 completion report.
