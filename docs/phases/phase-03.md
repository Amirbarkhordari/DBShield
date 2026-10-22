# Phase 3: HTTP Request Handling and Authentication Management — Completion Report

## 1. Phase Objectives

Design, implement, test, and document a reusable, scope-aware HTTP request layer and authentication/session management capability for the DBShield security testing framework.

This layer provides:
- Outbound HTTP request execution for standard HTTP methods (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).
- Reusable session management with target-bound origin isolation.
- Support for key authentication methods: unauthenticated, Bearer token, HTTP Basic, custom headers, and session cookies.
- Automatic cookie jar persistence across sequential requests within an authorized session.
- Cross-origin redirect credential isolation (stripping sensitive `Authorization` headers and `Cookie` values when redirecting to a different origin, even when both origins are within the broad authorized scope).
- Bounded response bodies with configurable limits (`max_response_size_bytes`) and truncation flags to avoid unbounded memory consumption.
- Case-insensitive response headers abstraction (`CaseInsensitiveDict` on `HTTPResponse`).
- CLI integration via `dbshield request` command with stream discipline, structured outputs (`text`, `json`), output file export with `--overwrite` protection, and strict secret masking.
- Deterministic automated unit and integration tests verifying all capabilities.

---

## 2. Scope and Exclusions

### In-Scope (Delivered)
- `SafeHTTPClient` extensions:
  - Methods: `get()`, `post()`, `put()`, `patch()`, `delete()`, `head()`, `options()`.
  - Configurable `max_response_size_bytes` (default 5MB) preventing memory exhaustion.
  - Pre-request scope validation before initial request.
  - Pre-redirect scope validation on each hop before following.
  - Cross-origin credential stripping on redirect hops.
  - Integration with `SessionManager`.
- Response Abstraction (`HTTPResponse`):
  - Normalized, case-insensitive headers lookup (`CaseInsensitiveDict` and `.get_header()`).
  - Duck-typing compatibility with `httpx.Response` (`.text`, `.content`, `.json()`).
  - Status classification properties (`.is_success`, `.is_redirect`, `.is_client_error`, `.is_server_error`).
  - Operational metadata: `elapsed_seconds`, `redirect_history`, `truncated`, `error_message`.
  - Serialized safe dictionary representation (`.to_safe_dict()`) with body preview truncation.
- Authentication Models (`AuthConfig`, `AuthType`, `AuthState`):
  - Supported methods: `none`, `bearer`, `basic`, `header`, `cookie`.
  - Strict parameter validation per authentication type.
  - Zero-leak credential representation: secrets masked as `[REDACTED]` in `to_safe_dict()` and `__repr__()`.
- Session Management (`SessionManager`):
  - Target-origin binding (`_normalize_origin()`, `bind_target()`).
  - Origin compatibility verification (`is_origin_compatible()`).
  - Cross-origin refusal: raises `AuthenticationError` if attempting to send credentials to a cross-origin target.
  - Cookie jar: parses `Set-Cookie` headers and retransmits cookies on subsequent requests.
  - Explainable state machine: 401 transitions to `UNAUTHENTICATED`; 403 preserves state; 200 transitions to `UNKNOWN` (never assumes `AUTHENTICATED` without proof).
  - Explicit session lifecycle: `reset()` and `invalidate()`.
- CLI Integration (`dbshield request`):
  - Parameters: `--url`, `--method`, `--header`, `--data`, `--json`, `--auth-type`, `--token`, `--username`, `--password`, `--cookie`, `--timeout`, `--follow-redirects`, `--max-redirects`, `--format` (`text`, `json`), `--output`, `--overwrite`.
  - Environment variable fallback for credentials (`DBSHIELD_AUTH_TOKEN`, `DBSHIELD_AUTH_USERNAME`, `DBSHIELD_AUTH_PASSWORD`).
  - Stream-disciplined output and Linux CLI Design System compliance (0: success, 1: operational/network error, 2: usage/scope error).
- Comprehensive test suite: expanded to 115 tests with 100% pass rate.

### Exclusions (Strictly Enforced)
- **Zero SQL / NoSQL Injection Payload Execution**: Completely deferred to Phases 4 and 5.
- **Zero Credential Guessing / Brute-Force Testing**: DBShield never guesses passwords, sprays credentials, or attacks logins.
- **Zero Automatic Form Submissions**: Authentication is configured explicitly by the operator; DBShield does not auto-submit forms.
- **Zero Website-Wide Crawling**: Requests are sent strictly to explicitly provided targets.
- **Zero Plaintext Secrets**: Passwords, tokens, and cookies are never printed in logs, terminals, or reports.

---

## 3. Files Created and Modified

| File | Change Type | Purpose |
| :--- | :--- | :--- |
| `src/dbshield/models/http.py` | Created | HTTP request and response models (`HTTPMethod`, `HTTPRequest`, `HTTPResponse`, `CaseInsensitiveDict`) |
| `src/dbshield/models/auth.py` | Created | Authentication configuration and lifecycle models (`AuthConfig`, `AuthType`, `AuthState`) |
| `src/dbshield/auth/manager.py` | Created | SessionManager providing origin isolation, cookie persistence, and auth state tracking |
| `src/dbshield/auth/__init__.py` | Created | Package export for `SessionManager` |
| `src/dbshield/exceptions.py` | Modified | Added `AuthenticationError(DBShieldError)` with diagnostic detail fields |
| `src/dbshield/models/__init__.py` | Modified | Exported HTTP and Authentication models |
| `src/dbshield/http/client.py` | Modified | Extended `SafeHTTPClient` with methods, response bounding, session integration, cross-origin credential stripping |
| `src/dbshield/discovery/engine.py` | Modified | Updated type annotations for `HTTPResponse` duck-typing compatibility |
| `src/dbshield/cli.py` | Modified | Added `request` command, argument parsing, report formatter, and exception handling |
| `tests/unit/test_http_models.py` | Created | 7 unit tests for HTTP request/response models and case-insensitive headers |
| `tests/unit/test_auth_config.py` | Created | 7 unit tests for AuthConfig validation, Base64 Basic auth, and secret redaction |
| `tests/unit/test_session_manager.py` | Created | 6 unit tests for SessionManager origin isolation, cookie jar, and state transitions |
| `tests/integration/test_safe_http_client_auth.py` | Created | 6 integration tests for HTTP methods, Bearer/Basic auth, cookie reuse, redirect stripping, and size limiting |
| `tests/integration/test_cli_request.py` | Created | 12 integration tests for `dbshield request` command |
| `README.md` | Modified | Updated project status, capabilities, CLI documentation, and test badge |
| `CHANGELOG.md` | Modified | Added `[0.3.0]` release section |
| `docs/architecture.md` | Modified | Documented HTTP and Auth architecture, session lifecycle, and cross-origin isolation |
| `docs/roadmap.md` | Modified | Marked Phase 3 as Completed |
| `docs/phases/phase-03.md` | Created | Authoritative Phase 3 completion report |

---

## 4. Key Architectural Decisions

### 4.1 Strict Origin Isolation
In security assessment tools, targets frequently belong to broader wildcard scopes (e.g. `*.example.com`). If an application at `app.example.com` redirects to `cdn.example.com` or `auth.example.com`, sending session cookies or Bearer tokens across origins violates the same-origin principle. DBShield enforces:
1. **At Dispatch**: `SessionManager.apply_auth()` checks that the destination matches the bound session origin (`scheme://host[:port]`). Any cross-origin attempt raises `AuthenticationError`.
2. **On Redirect**: If an in-scope request is redirected to a different host/origin, `SafeHTTPClient` automatically strips the `Authorization` header, any configured custom authentication headers, and all cookies before following the redirect.

### 4.2 Safe Response Bounding
Real-world HTTP responses can be arbitrarily large (e.g. large file downloads, database dumps). `SafeHTTPClient` introduces `max_response_size_bytes` (default 5MB). If the response body exceeds this budget:
- The byte stream is truncated to `max_response_size_bytes`.
- The `HTTPResponse.truncated` flag is set to `True`.
- A warning is recorded in diagnostic logs.
- Memory exhaustion risks are eliminated.

### 4.3 Duck-Typing Backward Compatibility
`HTTPResponse` exposes `.text`, `.content`, `.json()`, `.status_code`, `.headers`, and `.url` so existing modules like `DiscoveryEngine` and Phase 1 test suites consume `HTTPResponse` seamlessly without code breaking or requiring adapters.

### 4.4 Conservative Authentication State Machine
A response with HTTP 200 OK does **not** prove that a request was authenticated (many applications return 200 with a login form or an error message). DBShield transitions `CONFIGURED` to `UNKNOWN` upon HTTP 200, transitions to `UNAUTHENTICATED` upon HTTP 401, and preserves state upon HTTP 403 (since 403 indicates authorization/permission restrictions, not necessarily expired credentials).

---

## 5. Verification Results

### Quality Checks
```bash
ruff check src tests          # All checks passed! (0 errors)
ruff format --check src tests # 38 files already formatted!
mypy src                      # Success: no issues found in 22 source files
pytest -v                     # 115 passed in 5.30s (100% pass rate)
```

### CLI Verification Examples
```bash
# Display request help
dbshield request --help

# Unauthenticated in-scope GET request
dbshield request --url https://authorized-target.example/api/v1/health

# Bearer token authenticated request with JSON output
dbshield request --url https://authorized-target.example/api/profile \
  --auth-type bearer \
  --token "auth-token-xyz" \
  --format json

# HTTP Basic authenticated request with export
dbshield request --url https://authorized-target.example/admin \
  --method GET \
  --auth-type basic \
  --username admin \
  --password "admin-pass" \
  --output request_report.txt \
  --overwrite
```

---

## 6. Known Limitations and Deferred Capabilities

1. **Active Payload Injection**: Deferred to Phase 4 (SQL Injection) and Phase 5 (NoSQL Injection).
2. **Automated Re-authentication Workflows**: Complex multi-step login flows (e.g. CSRF token scraping + form POST) will be integrated in future phases when engine workflows are introduced.
3. **Burp Suite Proxy Binding**: Upstream proxy routing and Burp Suite extension bindings are scheduled for Phase 10.
