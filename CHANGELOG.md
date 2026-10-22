# Changelog

All notable changes to the **DBShield** framework are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
