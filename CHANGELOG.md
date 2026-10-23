# Changelog

All notable changes to the **DBShield** framework are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Phase 7 Evidence Analysis and Vulnerability Verification Engine**: Dedicated subsystem (`dbshield.verification`) for cross-engine evidence normalization, candidate correlation, explainable confidence evaluation, and lifecycle state management.
- **Evidence Normalization & Provenance Model (`NormalizedEvidence`, `EvidenceProvenance`)**: Standardized evidence representation preserving links to original test cases, payloads, and executions, with automated credential scrubbing.
- **Evidence Correlation & Deduplication (`EvidenceCorrelator`)**: Deterministic grouping by canonical target URL, vulnerability class, transport location, and parameter name with duplicate suppression and audit logging.
- **Explainable Confidence Assessor (`ConfidenceAssessor`)**: Transparent multi-factor scoring (0.0 to 1.0) distinguishing observation certainty from vulnerability exploitability certainty, evaluating database error specificity, baseline stability, differential divergence, and detector agreement.
- **Formal Verification State Machine (`VerificationStateMachine`)**: Explicit 8-state finding lifecycle with strict transition graph enforcement, domain prerequisite checks, and immutable transition audit logging.
- **False-Positive Elimination Rules**: Deterministic rejection of pre-existing baseline errors, generic HTTP 400/500 errors lacking database error patterns, unstable baselines, and contradictory responses.
- **CLI Verify Command (`dbshield verify`)**: Command-line verification interface supporting offline execution results (`--input`), response fixtures (`--fixture`), and live scope-checked execution assessment (`--url`).
- **Expanded Test Suite**: Added 52 new unit and integration tests (343 total tests passing 100%, 86% overall project coverage, 94% verification package coverage, clean Ruff and Mypy).

### Security
- **Pure Offline Verification**: Evidence analysis executes strictly in-memory without initiating network requests.
- **Defensive Safety Architecture**: Zero active exploitation, zero database dumping, zero schema extraction, and bounded request budgets.
- **Zero-Secret Reporting**: Strict redaction of authentication headers, bearer tokens, cookies, JWTs, and sensitive parameter references from evidence snippets and assessment reports.
- **Scope Verification**: Live CLI assessment strictly enforces `ScopeManager` pre-flight authorization.

## [0.6.0] - 2026-10-22

### Added
- **Phase 6 Payload Management and Test Execution Engine**: Common reusable foundation for managing test payloads, isolated input mutation, execution budgeting, engine orchestration, and structured result tracking.
- **Centralized Payload Catalog (`PayloadCatalog`)**: Decoupled, data-driven security payload repository supporting categories (`sqli`, `nosqli`, `generic`), risk classifications, locations, provider hints, paired roles, and safety constraints.
- **Deterministic Filtering & Catalog Integrity Verification**: Programmatic and CLI filtering by engine, category, location, technique, provider family, risk level, and tags with reciprocal paired payload validation.
- **Isolated Parameter Transformer (`PayloadTransformer`)**: Non-destructive request variant generator using deep copies to mutate query parameters (flat, repeated, Express bracket notation), URL-encoded forms, and nested JSON structures (dot-paths, array indices) without altering caller-owned objects.
- **Execution Policy & Budget Tracker (`ExecutionPolicy`, `ExecutionBudgetTracker`)**: Centralized enforcement of global request ceilings, per-parameter request limits, timeouts, cancellation controls, and sensitive parameter filtering (passwords, tokens, nonces).
- **Engine Adapters (`SQLiExecutionAdapter`, `NoSQLiExecutionAdapter`)**: Typed adapters connecting shared execution lifecycles to Phase 4 and 5 error and differential detectors without duplicating classification logic.
- **Test Execution Orchestrator (`TestExecutionOrchestrator`)**: Common lifecycle coordination: scope enforcement, candidate parameter extraction, baseline characterization, payload selection, isolated variant generation, bounded HTTP execution, and structured result collection. Supports offline response fixture analysis.
- **CLI Payloads Command (`dbshield payloads`)**: Inspect, list, filter, validate, and export payload definitions.
- **CLI Execute Command (`dbshield execute`)**: Controlled multi-engine security test execution across online targets and offline JSON response fixtures.
- **Expanded Test Suite**: Added 55 new unit and integration tests (291 total tests passing 100%, 86% overall statement coverage, clean Ruff and Mypy).

### Security
- **Inert Data Guarantee**: Payloads exist as inert metadata and never independently trigger network traffic.
- **Strict Scope Boundaries**: Rejects out-of-scope targets prior to any network dispatch.
- **Defensive & Read-Only**: Strictly excludes data extraction, database dumping, authentication bypass, data destruction, and DoS timing probes.
- **Sensitive Parameter Skipping**: Sensitive credentials (passwords, auth tokens, CSRF tokens, session IDs) are automatically skipped from payload delivery.
- **Redaction Controls**: Secrets are redacted from logs, evidence snippets, and serialized execution results.
- **Strict Request Ceilings**: All execution policies and request budgets are enforced at the execution layer.

### Added
- **Phase 5 NoSQL Injection Detection Engine**: Dedicated defensive assessment engine for detecting document database syntax errors, driver exceptions, and operator differential signals.
- **CLI NoSQLi Command (`dbshield nosqli`)**: CLI entry point supporting target URLs, candidate parameter filtering, request budgets, authentication injection, JSON export, and offline fixture assessment.
- **Nested JSON Parameter Extraction & Mutation**: Recursive discovery of candidate dot-delimited key paths (e.g. `filter.user_id`) and isolated deep mutation preserving all sibling keys and outer schema structures.
- **MongoDB Error Signature Catalog**: Curated signatures for operator rejection (`unknown operator`), query canonicalization, `$where` JavaScript syntax errors, PyMongo `OperationFailure`, BSON serialization exceptions, Mongoose `CastError`, and regular expression errors.
- **CouchDB Error Signature Catalog**: Signatures for JavaScript view compilation errors, Mango query selector syntax errors, and invalid selector exceptions.
- **Generic NoSQL Signatures**: Generic document store query syntax and client exception recognition.
- **MongoDB ObjectId Normalization**: Automatic masking of 24-hex-character MongoDB ObjectIds (`ObjectId("...")` and raw 24-hex hashes) as `[DYNAMIC_OBJECTID]` to prevent false divergence in similarity scoring.
- **Operator & Boolean Differential Detector (`NoSQLDifferentialDetector`)**: Compares paired truthy (e.g. `$ne` sentinel) and falsy (e.g. `$in: []` or `$eq`) responses against baseline.
- **NoSQL Error Detector (`NoSQLErrorDetector`)**: Rejects generic 400/500 errors without database signatures and filters pre-existing baseline database faults.
- **Offline Response Fixture Analysis**: Support for `--fixture <path>` enabling deterministic, zero-network laboratory validation from recorded JSON response fixtures.
- **Expanded Test Suite**: Added 51 new unit and integration tests (236 total tests passing 100%, 88% statement coverage).

### Security
- **Defensive Assessment Only**: Strictly prohibits collection dumping, document exfiltration, record modification, automated exploitation, or denial-of-service timing queries.
- **Zero-Credential Testing**: Passwords, auth tokens, and session nonces are excluded from test input delivery.
- **Snippet Secret Redaction**: Response snippets captured in evidence records automatically redact passwords, API tokens, and session cookies.
- **Request Budget Ceilings**: Strict per-parameter (`max_param_budget`) and per-scan (`max_budget`) ceilings prevent resource exhaustion.

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
