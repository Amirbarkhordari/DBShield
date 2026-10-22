# Changelog

All notable changes to the **DBShield** framework are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
