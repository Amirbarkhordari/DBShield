# Errors, Logging, and Exit Codes

This document establishes the standards for diagnostic error messages, logging verbosity, credential masking, and POSIX exit code contracts.

---

## 1. The 3-Part Error Anatomy

Cryptic error messages (such as `Error: -1` or unformatted raw stack traces) waste operator time and break automation. Every error emitted to the terminal must answer three questions:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        3-PART ERROR ANATOMY                            │
├───────────────┬────────────────────────────────────────────────────────┤
│ 1. WHAT       │ Exactly which operation or resource failed             │
│ 2. WHY        │ The root cause or underlying system reason (if known)  │
│ 3. NEXT STEPS │ The specific remediation action or flag to try next    │
└───────────────┴────────────────────────────────────────────────────────┘
```

### Example:
```text
[-] Error: Unable to bind to port 443 on interface 0.0.0.0.
    Cause: Permission denied (errno 13). Ports below 1024 require superuser privileges.
    Remedy: Run the command with 'sudo', or choose a port above 1024 using '--port 8443'.
```

### Contrast With Bad Practices:
- **Bad**: `ConnectionError: [Errno 111] Connection refused`
- **Good**:
  ```text
  [-] Error: Failed to connect to database host 'db.internal.net:5432'.
      Cause: Connection refused. The database server is either down or not listening on this port.
      Remedy: Verify database status with 'systemctl status postgresql' or check firewall rules.
  ```

---

## 2. Standard POSIX Exit Codes

Exit codes are the contract between your CLI and the calling shell, script, or CI runner. Never exit with `0` on error, and never use random arbitrary exit numbers.

| Exit Code | Name / Meaning | Use Case |
| :--- | :--- | :--- |
| `0` | **Success** | Operation completed successfully with no fatal errors. |
| `1` | **General Operational Error** | Runtime failure (e.g. host unreachable, target returned HTTP 500, task failed). |
| `2` | **Usage / Syntax Error** | Invalid flags, missing required arguments, mutually exclusive options passed. |
| `3` | **Configuration Error** | Missing or malformed config file, invalid environment variable format. |
| `4` | **Network / I/O Error** | Network timeout, DNS resolution failure, socket connection reset. |
| `5` | **Permission Denied** | Insufficient filesystem or OS privileges (non-root when root is required). |
| `126`| **Command Cannot Execute** | Executable found but lacks execution permissions. |
| `127`| **Command Not Found** | Required external dependency or binary (e.g. `nmap`, `iptables`) is missing. |
| `130`| **Terminated by Ctrl+C** | Process killed via `SIGINT` (standard: 128 + signal 2). |
| `143`| **Terminated by SIGTERM** | Process gracefully stopped by supervisor or `systemd` (128 + signal 15). |

---

## 3. Logging Verbosity and Diagnostics

Support progressive verbosity levels:

| Level | Flag | Intended Audience & Content |
| :--- | :--- | :--- |
| **Quiet** | `-q`, `--quiet` | Output only final payloads and critical errors. Zero banners or status lines. |
| **Normal** | (default) | Status prefixes `[+]`, `[-]`, `[*]`, clean tables, summaries. |
| **Verbose** | `-v` | Diagnostic details, step timing, skipped items, network headers. |
| **Debug** | `-vv` or `--debug` | Raw HTTP request/response payloads, full exception stack traces, internal state. |

### Stack Trace Handling
- In **normal mode**, catch internal unhandled exceptions and display a user-friendly error line:
  ```text
  [-] An unexpected internal error occurred: [Errno 28] No space left on device.
      Use '--debug' to view the full execution traceback.
  ```
- In **debug mode** (`--debug`), display the full language stack trace to assist developers and maintainers in debugging.

---

## 4. Credential Masking & Redaction

Command-line logs, error messages, and reports must **never** leak sensitive information (passwords, bearer tokens, AWS keys, private keys).

### Redaction Rules
1. **Mask Sensitive Flags**: If an API key or password must be logged, redact all but the first 4 and last 2 characters:
   ```text
   [*] Authenticating with API token: eyJhbG...x9
   ```
2. **Redact Authorization Headers in Debug Logs**:
   ```text
   > Authorization: Bearer [REDACTED]
   ```
3. **URL Parameter Scrubbing**: Strip query parameters like `?token=...`, `?key=...`, or `?password=...` from printed request URLs.
