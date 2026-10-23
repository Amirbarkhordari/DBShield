# DBShield Development Roadmap

This document outlines the authoritative 10-phase engineering roadmap for the DBShield framework.

---

## Roadmap Overview

```
Phase 1: Project Foundation & Core Architecture        [COMPLETED]
Phase 2: Login-Page Discovery & Form Analysis          [COMPLETED]
Phase 3: HTTP Request Handling & Authentication        [COMPLETED]
Phase 4: SQL Injection Testing Engine                  [COMPLETED]
Phase 5: NoSQL Injection Testing Engine                [COMPLETED]
Phase 6: Payload Management & Test Execution           [COMPLETED]
Phase 7: Evidence Analysis & Verification              [COMPLETED]
Phase 8: Result Presentation & Report Generation       [PLANNED]
Phase 9: Laboratory Validation & Stabilization         [PLANNED]
Phase 10: Whole-App Expansion & Burp Suite Integration [PLANNED]
```

---

## Detailed Phase Status

### Phase 1: Project Foundation and Core Architecture
- **Status**: **Completed**
- **Deliverables**:
  - Python package setup (`pyproject.toml`, editable install)
  - Typer CLI with `doctor`, `inspect`, and `info` commands
  - Pydantic Settings configuration management
  - Target and Scan foundational data models
  - Target Scope Manager (`ScopeManager`)
  - Safe, scope-aware HTTP client (`SafeHTTPClient`)
  - Structured logging with sensitive-data redaction
  - Automated test suite (45 tests, 100% pass)
  - Comprehensive Phase 1 documentation

---

### Phase 2: Login-Page Discovery and Form Analysis
- **Status**: **Completed**
- **Deliverables**:
  - Typer CLI `dbshield discover` command with `--format` (`text`, `json`) and `--output` options
  - Tolerant HTML parser (`HTMLFormParser`) handling forms, actions, methods, encodings, and orphan controls
  - Relative action normalization, missing action document defaults, and URL fragment stripping
  - Rule-based heuristic classifier (`DiscoveryClassifier`) identifying usernames, emails, passwords, OTPs, and CSRF tokens
  - Origin comparison (same-origin vs cross-origin) and out-of-scope action detection without sending requests
  - Validated Pydantic models: `DiscoveryResult`, `DiscoveredForm`, `InputField`, `DiscoverySummary`
  - Automated test suite expanded to 77 tests (100% pass, clean Ruff and Mypy)
  - Zero-credential safety, zero form submissions, zero active payload execution

---

### Phase 3: HTTP Request Handling and Authentication
- **Status**: **Completed**
- **Deliverables**:
  - Typer CLI `dbshield request` command with methods, headers, data/json bodies, and auth options
  - Safe HTTP client (`SafeHTTPClient`) with methods (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
  - Memory-safe bounded response bodies with `max_response_size_bytes` and truncation indicators
  - Structured response abstraction (`HTTPResponse`) with case-insensitive headers (`CaseInsensitiveDict`)
  - Authentication configuration (`AuthConfig`) supporting None, Bearer, Basic, Header, and Cookie auth
  - Target-bound session management (`SessionManager`) with origin isolation and cookie jar persistence
  - Cross-origin redirect credential stripping (stripping `Authorization` and cookies across origins)
  - Conservative authentication state evaluation (distinguishing unknown states from confirmed failures)
  - Automated test suite expanded to 115 tests (100% pass rate, clean Ruff and Mypy)

---

### Phase 4: SQL Injection Testing Engine
- **Status**: **Completed**
- **Deliverables**:
  - Typer CLI `dbshield sqli` command with parameter targeting, budget limits, formats, and offline fixtures
  - Modular SQL injection engine (`SQLiEngine`) reusing `SafeHTTPClient`, `ScopeManager`, and `SessionManager`
  - Baseline response characterization (`BaselineCharacterizer`) verifying stability across multi-probe samples
  - Error-based SQL injection detector (`ErrorDetector`) with curated signature catalog across 6 DB families
  - Boolean differential detector (`DifferentialDetector`) comparing paired logical conditions against baseline
  - Dynamic token masking (`ResponseNormalizer`) eliminating volatile timestamps, UUIDs, and CSRF tokens
  - Zero-credential safety filter automatically skipping passwords, auth tokens, and session nonces
  - Structured immutable finding models (`SQLiFinding`, `SQLiScanResult`, `EvidenceRecord`)
  - Offline fixture analysis mode enabling zero-network laboratory validation
  - Automated test suite expanded to 177 tests (100% pass rate, clean Ruff and Mypy)

---

### Phase 5: NoSQL Injection Testing Engine
- **Status**: **Completed**
- **Deliverables**:
  - Typer CLI `dbshield nosqli` command with parameter targeting, budget limits, formats, and offline fixtures
  - Modular NoSQL injection engine (`NoSQLiEngine`) reusing `SafeHTTPClient`, `ScopeManager`, and `SessionManager`
  - Nested JSON parameter extraction and isolated key-path mutation preserving full document structures
  - Baseline response characterization (`NoSQLBaselineCharacterizer`) verifying stability across multi-probe samples
  - Error-based NoSQL detector (`NoSQLErrorDetector`) with curated signature catalog across MongoDB, CouchDB, and generic NoSQL
  - Operator and boolean differential detector (`NoSQLDifferentialDetector`) comparing paired conditions against baseline
  - Dynamic token masking (`NoSQLResponseNormalizer`) eliminating volatile timestamps, UUIDs, CSRF tokens, and MongoDB ObjectIds
  - Zero-credential safety filter automatically skipping passwords, auth tokens, and session nonces
  - Structured immutable finding models (`NoSQLFinding`, `NoSQLScanResult`, `NoSQLEvidenceRecord`)
  - Offline fixture analysis mode enabling zero-network laboratory validation
  - Automated test suite expanded to 236 tests (100% pass rate, clean Ruff and Mypy)

---

### Phase 6: Payload Management and Test Execution
- **Status**: **Completed**
- **Deliverables**:
  - Centralized, typed payload catalog (`PayloadCatalog`, `SecurityPayload`) decoupled from execution logic
  - Deterministic payload filtering by engine, category, location, technique, provider, and risk rating
  - Isolated parameter mutation engine (`PayloadTransformer`) for query, form, and nested JSON structures
  - Centralized execution policy and budget enforcement (`ExecutionPolicy`, `ExecutionBudgetTracker`)
  - Typed engine adapters (`SQLiExecutionAdapter`, `NoSQLiExecutionAdapter`) integrating Phase 4 and 5 detectors
  - Shared execution orchestrator (`TestExecutionOrchestrator`) coordinating parameter discovery, scope checks, and safe execution
  - CLI `dbshield payloads` command for catalog inspection, filtering, and validation
  - CLI `dbshield execute` command for multi-engine online assessment and offline fixture analysis
  - Automated test suite expanded to 291 tests (100% pass rate, 86% coverage, clean Ruff and Mypy)

---

### Phase 7: Evidence Analysis and Vulnerability Verification
- **Status**: **Completed**
- **Deliverables**:
  - Normalized evidence architecture (`NormalizedEvidence`, `EvidenceProvenance`) preserving full execution traceability
  - Credential and token scrubbing from snippets, parameters, and serialized assessment reports
  - Deterministic candidate correlation and deduplication (`EvidenceCorrelator`) maintaining finding isolation
  - Explainable confidence rubric (`ConfidenceAssessor`) evaluating observation vs exploitability certainty
  - Formal finding lifecycle state machine (`VerificationStateMachine`) enforcing prerequisites and audit trails
  - False-positive elimination filters for pre-existing baseline errors, generic server codes, and noisy baselines
  - Dedicated CLI command `dbshield verify` supporting offline results (`--input`), fixtures (`--fixture`), and live scans (`--url`)
  - Automated test suite expanded to 343 tests (100% pass rate, 86% overall coverage, 94% verification coverage, clean Ruff and Mypy)

---

### Phase 8: Result Presentation and Reporting
- **Status**: **Planned**
- **Scope**:
  - Rich terminal summaries with severity categorization
  - Structured JSON report export
  - Compliance and executive summary report generation (Markdown/HTML)

---

### Phase 9: Laboratory Validation and Stabilization
- **Status**: **Planned**
- **Scope**:
  - Benchmarking against OWASP Juice Shop, DVWA, and custom testbeds
  - Performance tuning and timeout calibration
  - Robustness audits across various Linux distributions

---

### Phase 10: Whole-Application Expansion and Burp Suite Integration
- **Status**: **Planned**
- **Scope**:
  - Upstream proxy configuration (HTTP/SOCKS5)
  - Burp Suite extension bindings (Montoya API)
  - Integration with CI/CD security pipelines
