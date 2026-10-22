# DBShield Architecture Specification

This document details the architectural design, module responsibilities, core abstractions, data flow, and extension points of the DBShield framework.

---

## 1. Architectural Philosophy

DBShield is engineered as a **modular, extensible security framework**, not a collection of ad-hoc testing scripts. Its design emphasizes:

1. **Decoupled Responsibilities**: Presentation (CLI), business logic (models/scope/classification), HTML parsing, configuration, and I/O (HTTP) are strictly isolated.
2. **Safety by Design**: Network requests cannot occur without passing through the `ScopeManager`, preventing accidental out-of-scope traffic. Form action URLs are evaluated against scope rules without sending any requests to them.
3. **Zero Credential Collection**: Discovery analyzes structural input points and form controls without storing real passwords, session secrets, or personal data.
4. **Explainable Heuristics**: Classification decisions provide transparent confidence scores and evidence trails.
5. **Extensibility for Multi-Phase Progression**: Phase 1 established foundational infrastructure; Phase 2 built the discovery engine; subsequent phases build request handling (Phase 3) and controlled database security engines (Phases 4–5).

---

## 2. Layered Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          PRESENTATION LAYER                             │
│                  (Typer CLI: dbshield.cli, __main__)                    │
│      Commands: doctor, inspect, info, discover, --version               │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Invokes
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         DISCOVERY LAYER                                 │
│                 (dbshield.discovery, dbshield.models.discovery)         │
│  ┌───────────────────────┐  ┌───────────────────────┐                   │
│  │    HTMLFormParser     │  │  DiscoveryClassifier  │                   │
│  │ (DOM & Form Control)  │  │ (Rule-Based Heuristic)│                   │
│  └───────────┬───────────┘  └───────────┬───────────┘                   │
│              └─────────────┬────────────┘                               │
│                            ▼                                            │
│                     DiscoveryEngine                                     │
│          (Orchestrates Retrieval & Classification)                      │
└───────────────────┬────────────────────────────────┬────────────────────┘
                    │                                │
                    ▼                                ▼
┌──────────────────────────────────────┐   ┌──────────────────────────────┐
│        SCOPE ENFORCEMENT             │   │   CONFIGURATION & LOGGING    │
│    (dbshield.scope.manager)          │   │  (dbshield.config, logging)  │
│  - Exact host matching               │   │  - Pydantic Settings         │
│  - Subdomain allowlist policy        │   │  - Redaction filter          │
│  - Redirect & Action pre-validation  │   │  - Structured 3-part errors  │
└───────────────────┬──────────────────┘   └──────────────────────────────┘
                    │ Governs
                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          I/O ADAPTER LAYER                              │
│                    (dbshield.http.SafeHTTPClient)                       │
│    - httpx wrapper with timeout budgets & redirect limits               │
│    - Intercepts every redirect hop to enforce scope revalidation        │
│    - Zero automatic form submission or website crawling                 │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module Responsibilities

### 3.1 `dbshield.config`
- Manages centralized settings using `pydantic-settings.BaseSettings`.
- Reads operational limits from environment variables (`DBSHIELD_*`) and optional `.env` files.
- Employs `LenientEnvSettingsSource` to allow either comma-separated strings or JSON arrays for `allowed_hosts`.
- Provides `get_safe_dict()` to present sanitized configuration views without secret leakage.

### 3.2 `dbshield.models.target`
- Parses user-provided URLs into immutable `Target` instances.
- Restricts schemes strictly to `http` and `https`.
- Normalizes hostnames to lowercase and computes effective ports (80/443 default).

### 3.3 `dbshield.models.scan`
- Represents assessment sessions with unique UUIDv4 identifiers.
- Tracks `ScanProfile` (Passive, Discovery, Standard, Aggressive) and `ScanStatus` (Pending, Initialized, Running, Completed, Failed, Aborted).
- Tracks planned vs executed test counters.

### 3.4 `dbshield.models.discovery`
- `FieldClassification`: Rule-based enum (`USERNAME`, `EMAIL`, `PASSWORD`, `OTP`, `CSRF_TOKEN`, `HIDDEN`, `GENERIC_INPUT`, `SUBMIT`, `UNKNOWN`).
- `PageClassification`: Overall page assessment enum (`LOGIN_FORM_DETECTED`, `MULTIPLE_LOGIN_FORMS`, `LOGIN_INPUTS_WITHOUT_FORM`, `NO_LOGIN_FORM_DETECTED`, `PAGE_COULD_NOT_BE_ANALYZED`, `PAGE_INACCESSIBLE_OR_BLOCKED`).
- `DiscoveryStatus`: Execution outcome enum (`COMPLETED`, `COMPLETED_WITH_WARNINGS`, `FAILED`, `BLOCKED_BY_SCOPE`).
- `InputField`: Detailed model for input controls, element tags, attributes, labels, required flags, confidence, and evidence. Values of sensitive fields are never collected.
- `DiscoveredForm`: Form model storing declared and resolved actions, HTTP methods, encodings, controls, query parameters, duplicate names, same-origin flags, and scope authorization status.
- `DiscoverySummary`: Aggregated metrics of discovered forms, login candidates, candidate fields, passwords, usernames, and CSRF tokens.
- `DiscoveryResult`: Complete immutable result model, fully serializable to valid JSON via `model_dump_json()`.

### 3.5 `dbshield.scope.manager`
- Serves as the central authorization firewall of the application.
- Supports exact host matching and optional subdomain recursion (`allow_subdomains=True`).
- Rejects similarly-named attacker domains (`example.com.attacker.com`, `attacker-example.com`).
- Pre-validates redirect destinations before they can be followed.
- Evaluates discovered form action URLs to determine whether they are in-scope without sending network traffic.

### 3.6 `dbshield.http.client`
- Wraps `httpx.Client` to enforce pre-request scope checks.
- Intercepts 3xx responses and re-validates `Location` headers against `ScopeManager`.
- Enforces timeout budgets and redirect hop limits.
- Supports dependency injection (`client` or `transport`) to enable complete offline mock testing.

### 3.7 `dbshield.discovery.parser` (`HTMLFormParser`)
- Parses HTML documents using BeautifulSoup with `html.parser` for high fault tolerance.
- Extracts page title and query parameters from base URL and action URLs.
- Associates `<label for="...">` and wrapping `<label>` texts with their controls.
- Normalizes relative form actions against document base URL using `urljoin`.
- Strips non-transmittable URL fragments (`#...`).
- Defaults missing or empty form actions to the current page URL per HTML specification.
- Discovers formless / orphan input controls rendered outside formal `<form>` tags.
- Detects duplicate input control names.

### 3.8 `dbshield.discovery.classifier` (`DiscoveryClassifier`)
- Completely decoupled from HTML parsing to allow independent rule additions.
- Employs word-boundary regular expressions and token normalization (hyphens/underscores/dots converted to tokens).
- Classifies controls into explicit categories with confidence ratings (0.0 to 1.0) and evidence strings.
- Form classification evaluates credential controls, CSRF tokens, action keywords, and submit button texts while penalizing registration/search forms.
- Compares origin between document URL and form action URL to detect cross-origin submissions.
- Aggregates form and orphan input findings to classify the overall page.

### 3.9 `dbshield.discovery.engine` (`DiscoveryEngine`)
- Orchestrates the full Phase 2 discovery lifecycle:
  1. Validates target URL syntax.
  2. Asserts target host is within authorized scope.
  3. Executes a single safe GET request via `SafeHTTPClient`.
  4. Passes response body to `HTMLFormParser`.
  5. Passes parsed DOM structures to `DiscoveryClassifier`.
  6. Evaluates each form action URL with `ScopeManager.is_url_in_scope()`—flagging out-of-scope actions and guaranteeing zero requests are dispatched to them.
  7. Calculates summary metrics and builds the immutable `DiscoveryResult`.

---

## 4. Discovery Data Flow

```
User CLI Input: `dbshield discover --url <URL>`
      │
      ▼
Target.from_url(URL) -> URL Validation & Scheme Enforcement
      │
      ▼
ScopeManager.assert_in_scope(Target)
      │
      ├─[Out of Scope]──> Returns BLOCKED_BY_SCOPE (Exit Code 2)
      │
      ▼ [In Scope]
SafeHTTPClient.get(Target) -> Single HTTP Request with Redirect Interception
      │
      ├─[Network / Timeout Error]──> Returns FAILED (Exit Code 1)
      │
      ▼ [200 OK HTML]
HTMLFormParser.parse(html, base_url)
      │ Forms, Controls, Query Params, Orphan Inputs
      ▼
DiscoveryClassifier.classify_control() & classify_form()
      │
      ▼
ScopeManager.is_url_in_scope(action_url)  <-- Evaluates action boundary
      │
      ▼
DiscoveryClassifier.classify_page()
      │
      ▼
Construct DiscoveryResult
      │
      ├──> CLI Terminal Summary (stderr diagnostics, stdout report)
      └──> JSON Export (--format json or --output <path>)
```

---

## 5. HTTP Request Handling & Authentication Layer (Phase 3)

### 5.1 Architecture Overview

The Phase 3 HTTP layer provides a safe, reusable transport and session management abstraction consumed by future scanning modules (SQLi, NoSQLi):

```
                      CLI (`dbshield request`)
                                │
                                ▼
                       AuthConfig & Target
                                │
                                ▼
                         SessionManager
            (Origin Binding, Cookie Jar, State Machine)
                                │
                  apply_auth()  │  Cross-origin check
                                ▼
                         SafeHTTPClient
       (Scope Verification, Timeout Budget, Size Limit Bounding)
                                │
            ┌───────────────────┴───────────────────┐
            ▼                                       ▼
    Out-of-Scope Target                     In-Scope Target
     (ScopeViolationError)                          │
                                                    ▼
                                            HTTP Request Dispatch
                                                    │
                                      ┌─────────────┴─────────────┐
                                      ▼                           ▼
                              Redirect Location             Response (2xx/4xx/5xx)
                                      │                           │
                              Cross-Origin Check                  ▼
                         (Strip Credentials if origin      Construct HTTPResponse
                            differs from initial)                 │
                                      │                           ▼
                                      └──────────────────> Update SessionManager
                                                            (Cookies & State)
```

### 5.2 Key Abstractions

1. **`SafeHTTPClient`**:
   - Scope authorization verified before initial dispatch and before each redirect hop.
   - Convenience helpers: `get()`, `post()`, `put()`, `patch()`, `delete()`, `head()`, `options()`.
   - Response size bounded to `max_response_size_bytes` (default: 5MB) preventing memory exhaustion.
   - Cross-origin redirect credential stripping: if destination origin differs from initial target origin, `Authorization` headers, custom auth headers, and `Cookie` values are scrubbed before proceeding.

2. **`HTTPResponse`**:
   - Normalized, case-insensitive headers via `CaseInsensitiveDict`.
   - Duck-typing matching `httpx.Response` (`.text`, `.content`, `.json()`).
   - Status classifications (`.is_success`, `.is_redirect`, `.is_client_error`, `.is_server_error`).
   - Operational metadata: `elapsed_seconds`, `redirect_history`, `truncated`, `error_message`.
   - Serialized safe dictionary representation (`.to_safe_dict()`).

3. **`AuthConfig`**:
   - Authentication modes: `none`, `bearer`, `basic` (Base64 encoded), `header`, `cookie`.
   - Strict validation of required credentials per auth mode.
   - Strict zero-leak guarantee: passwords, tokens, cookies, and sensitive headers masked as `[REDACTED]` in `to_safe_dict()` and `__repr__()`.

4. **`SessionManager`**:
   - Origin-bound session isolation (`target_origin = scheme://host[:port]`).
   - Cross-origin refusal: raises `AuthenticationError` if attempting to send credentials to cross-origin targets.
   - Cookie store: parses `Set-Cookie` headers and automatically supplies cookies on subsequent same-origin requests.
   - Conservative state machine: 401 transitions to `UNAUTHENTICATED`; 403 preserves state; 200 transitions `CONFIGURED` to `UNKNOWN` (never assumes `AUTHENTICATED` without proof).
   - Explicit lifecycle controls: `reset()` and `invalidate()`.

---

---

## 6. SQL Injection Detection Engine (Phase 4)

### 6.1 Architecture Overview

The Phase 4 SQL Injection Detection Engine provides modular, defensive, and explainable vulnerability assessment routines:

```
                            CLI (`dbshield sqli`)
                                      │
                                      ▼
                        Candidate Parameter Extraction
                     (URL Query, Form Body, JSON Body)
                                      │
                                      ▼
                            Safety & Scope Firewall
              - ScopeManager.assert_in_scope()
              - Ineligible Parameter Filter (Skip Passwords/Tokens)
                                      │
                                      ▼
                           Baseline Characterization
                   (2 Sample Probes, Stability Verification)
                                      │
                 ┌────────────────────┴────────────────────┐
                 ▼                                         ▼
         Stable Baseline                          Unstable Baseline
                 │                               (Mark INCONCLUSIVE)
                 ├─────────────────────────────────────────┐
                 ▼                                         ▼
        Error-Based Detector                     Differential Detector
   (Match 6 Database Families               (Paired True/False Probes,
    vs Baseline Error Catalog)                Volatile Token Masking)
                 │                                         │
                 └────────────────────┬────────────────────┘
                                      │
                                      ▼
                             Construct Findings
             (`POTENTIAL_INDICATOR`, `NO_INDICATOR`, `INCONCLUSIVE`)
                                      │
                                      ▼
                          Terminal & JSON Reports
```

### 6.2 Key Abstractions

1. **`SQLiEngine`**:
   - Coordinates parameter extraction, scope pre-flight validation, and budget ceilings.
   - Dispatches safe, read-only probes and collects structured findings.
   - Supports offline response fixture analysis via `analyze_fixture_records()`.

2. **`BaselineCharacterizer`**:
   - Probes endpoints to profile status codes, content lengths, headers, and normalized body hashes.
   - Detects status fluctuations or excessive response drift, flagging unstable baselines as `INCONCLUSIVE`.

3. **`ResponseNormalizer`**:
   - Deterministically masks volatile dynamic elements (ISO/RFC timestamps, UUIDs, CSRF tokens, epochs).
   - Computes structural similarity ratios using `difflib.SequenceMatcher`.

4. **`SignatureCatalog` & `ErrorDetector`**:
   - Curated catalog for MySQL/MariaDB, PostgreSQL, SQLite, MSSQL, Oracle, and Generic ANSI SQL.
   - Explicitly rejects generic HTTP 500/400 errors lacking database signatures.
   - Discards pre-existing baseline errors to eliminate false positives.

5. **`DifferentialDetector`**:
   - Evaluates paired conditions (True vs False) against baseline.
   - Flags candidate findings only when the True condition matches baseline and False condition stably diverges.

---

## 7. Extension Points for Future Phases

| Phase | Module | Integration Point & Planned Responsibility | Status |
| :--- | :--- | :--- | :--- |
| **Phase 1: Foundation** | `dbshield.core` | Core models, ScopeManager, SafeHTTPClient, config, CLI foundation. | **Completed** |
| **Phase 2: Login Discovery** | `dbshield.discovery` | Passive HTML login-page retrieval, form and input classification. | **Completed** |
| **Phase 3: Auth & Sessions** | `dbshield.auth` / `dbshield.http` | Reusable HTTP layer, origin-isolated sessions, cookie jar, auth. | **Completed** |
| **Phase 4: SQLi Engine** | `dbshield.sqli` | Controlled SQL injection detection routines against target inputs. | **Completed** |
| **Phase 5: NoSQLi Engine** | `dbshield.engines.nosqli` | Controlled NoSQL injection detection routines. | Planned |
| **Phase 6: Payload Execution**| `dbshield.payloads` | Payload generation, mutation, and safe rate-limited delivery. | Planned |
| **Phase 7: Evidence Analysis**| `dbshield.analysis` | Response anomaly detection, error pattern matching, differential analysis.| Planned |
| **Phase 8: Reporting** | `dbshield.reporting` | Formatted JSON, HTML, and Markdown assessment summaries. | Planned |
| **Phase 9: Lab Validation** | `tests.lab` | Automated test suite execution against isolated test targets. | Planned |
| **Phase 10: Burp Suite** | `dbshield.integrations` | Upstream proxy adapters and Burp Suite extension bindings. | Planned |
