# DBShield Architecture Specification

This document details the architectural design, module responsibilities, core abstractions, and extension points of the DBShield framework.

---

## 1. Architectural Philosophy

DBShield is engineered as a **modular, extensible security framework**, not a collection of ad-hoc testing scripts. Its design emphasizes:

1. **Decoupled Responsibilities**: Presentation (CLI), business logic (models/scope), configuration, and I/O (HTTP) are strictly separated.
2. **Safety by Design**: Network requests cannot occur without passing through the `ScopeManager`, preventing accidental out-of-scope traffic.
3. **Extensibility for Multi-Phase Progression**: Phase 1 provides foundational hooks for Phase 2 (discovery), Phase 3 (authentication), and Phase 4/5 (SQLi/NoSQLi engines) without premature complexity.

---

## 2. Layered Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          PRESENTATION LAYER                             │
│                  (Typer CLI: dbshield.cli, __main__)                    │
│   Commands: doctor, inspect, info, --version, (future: scan, report)    │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Invokes
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         CORE & DOMAIN MODELS                            │
│           (dbshield.models.target, dbshield.models.scan)                │
│    - Target: URL normalization, scheme & port validation                │
│    - Scan: Session lifecycle, test counters, execution state            │
└───────────────────┬────────────────────────────────┬────────────────────┘
                    │ Validated by                   │ Ingests
                    ▼                                ▼
┌──────────────────────────────────────┐   ┌──────────────────────────────┐
│        SCOPE ENFORCEMENT             │   │   CONFIGURATION & LOGGING    │
│    (dbshield.scope.manager)          │   │  (dbshield.config, logging)  │
│  - Exact host matching               │   │  - Pydantic Settings         │
│  - Subdomain allowlist policy        │   │  - Redaction filter          │
│  - Redirect pre-validation           │   │  - Structured 3-part errors  │
└───────────────────┬──────────────────┘   └──────────────────────────────┘
                    │ Governs
                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          I/O ADAPTER LAYER                              │
│                    (dbshield.http.SafeHTTPClient)                       │
│    - httpx wrapper with timeout budgets & redirect limits               │
│    - Intercepts every redirect hop to enforce scope revalidation        │
│    - Dependency injection for unit & integration testing                │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module Responsibilities

### 3.1 `dbshield.config`
- Manages centralized settings using `pydantic-settings.BaseSettings`.
- Reads operational limits from environment variables (`DBSHIELD_*`) and optional `.env` files.
- Provides `get_safe_dict()` to present sanitized configuration views without secret leakage.

### 3.2 `dbshield.models.target`
- Parses user-provided URLs into immutable `Target` instances.
- Restricts schemes strictly to `http` and `https`.
- Normalizes hostnames to lowercase and computes effective ports (80/443 default).

### 3.3 `dbshield.models.scan`
- Represents assessment sessions with unique UUIDv4 identifiers.
- Tracks `ScanProfile` (Passive, Discovery, Standard, Aggressive) and `ScanStatus` (Pending, Initialized, Running, Completed, Failed, Aborted).
- Tracks planned vs executed test counters.

### 3.4 `dbshield.scope.manager`
- Serves as the central authorization firewall of the application.
- Supports exact host matching and optional subdomain recursion (`allow_subdomains=True`).
- Rejects similarly-named attacker domains (`example.com.attacker.com`, `attacker-example.com`).
- Pre-validates redirect destinations before they can be followed.

### 3.5 `dbshield.http.client`
- Wraps `httpx.Client` to enforce pre-request scope checks.
- Intercepts 3xx responses and re-validates `Location` headers against `ScopeManager`.
- Enforces timeout budgets and redirect hop limits.
- Supports dependency injection (`client` or `transport`) to enable complete offline mock testing.

### 3.6 `dbshield.logging_config`
- Implements `SensitiveDataFilter` to scrub bearer tokens, cookies, passwords, JWTs, and API keys from log streams.
- Formats logs with timestamps, module names, severities, and correlation IDs.

---

## 4. Extension Points for Future Phases

| Future Phase | Integration Point | Planned Responsibility |
| :--- | :--- | :--- |
| **Phase 2: Login Discovery** | `dbshield.discovery` | Analyzes target HTML for login forms, input fields, and endpoints using `SafeHTTPClient`. |
| **Phase 3: Auth & Sessions** | `dbshield.auth` | Manages authenticated sessions, cookie stores, and CSRF token handling. |
| **Phase 4: SQLi Engine** | `dbshield.engines.sqli` | Executes controlled SQL injection detection routines against target inputs. |
| **Phase 5: NoSQLi Engine** | `dbshield.engines.nosqli` | Executes NoSQL (MongoDB, CouchDB) injection detection routines. |
| **Phase 8: Reporting** | `dbshield.reporting` | Generates structured JSON, HTML, and Markdown assessment summaries. |
| **Phase 10: Burp Suite** | `dbshield.integrations` | Upstream proxy adapters and Burp Suite extension bindings. |
