# Output and Reporting Standards

This document establishes the architecture for stream separation, structured machine-readable formats (JSON, CSV), file export reliability, and atomic output persistence.

---

## 1. Stream Separation Architecture

The POSIX standard provides two standard output streams for every process: `stdout` (file descriptor 1) and `stderr` (file descriptor 2). CLI tools must rigorously separate their data streams.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        STREAM DISCIPLINE                                │
├──────────────────────────┬──────────────────────────────────────────────┤
│ STDOUT (FD 1)            │ Primary command data, query results,         │
│ (The Payload Stream)     │ structured JSON/CSV payloads, pipeline data  │
├──────────────────────────┼──────────────────────────────────────────────┤
│ STDERR (FD 2)            │ Progress bars, spinners, status notices,     │
│ (The Diagnostic Stream)  │ warnings, error traces, completion summaries │
└──────────────────────────┴──────────────────────────────────────────────┘
```

### Why This is Mandatory:
- Allows operators to pipe data safely into utilities like `jq`, `grep`, or `awk`:
  ```bash
  # Even with progress bars running, this must succeed without JSON parse errors:
  netpulse scan --target 10.0.0.1 --json | jq '.data.open_ports[]'
  ```
- If spinners or `[+] Starting scan` notices are printed to `stdout`, piping to `jq` immediately crashes with `parse error: Invalid numeric literal at line 1`.

---

## 2. Machine-Readable Formats

Support structured data export via `--format <type>` and convenient shortcuts like `--json`:
- Supported types: `text` (human default), `json` (machine standard), `csv` (tabular export), `yaml` (config/k8s workflows).

### 2.1 The JSON Purity Rule
When `--format json` or `--json` is selected:
1. **Zero ANSI Color Codes**: Never emit `\033[...]` sequences to `stdout`.
2. **Zero Banners or Footers**: Do not emit startup logos or "Execution complete" text to `stdout`.
3. **Zero Progress Logs on Stdout**: All progress bars must be directed to `stderr` or suppressed entirely.
4. **Valid JSON**: The entire content of `stdout` must parse cleanly with `jq .` or `json.loads()`.

---

## 3. Standard JSON Envelope Schema

All JSON output must follow a predictable, stable top-level envelope schema:

```json
{
  "schema_version": "1.0.0",
  "tool": "netpulse",
  "version": "2.4.0",
  "timestamp": "2026-10-22T08:15:00Z",
  "status": "success",
  "data": {
    "targets_scanned": 1,
    "findings": [
      {
        "id": "FIND-001",
        "host": "192.168.1.10",
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "banner": "nginx/1.24.0"
      }
    ]
  },
  "summary": {
    "total": 1,
    "vulnerabilities_detected": 0,
    "elapsed_seconds": 1.42
  },
  "errors": []
}
```

### Top-Level Fields:
- **`schema_version`** (string): Semantic version of the JSON schema (allows downstream parsers to handle schema migrations).
- **`tool`** & **`version`** (string): Originating utility and its release version.
- **`timestamp`** (ISO 8601 UTC): Exact execution start time.
- **`status`** (string): `"success"`, `"partial"`, or `"error"`.
- **`data`** (object/array): The actual operational payload.
- **`summary`** (object): Aggregated counters, timings, and high-level results.
- **`errors`** (array): List of diagnostic error objects encountered during execution.

---

## 4. File Export and Atomic Writes

When outputting to a file via `-o` or `--output <filepath>`:

### 4.1 Atomic Writing via Temporary Files
Never write directly to the target destination if a crash or interruption would leave a corrupted, half-written file.
1. Create a temporary file in the same directory (or `/tmp`):
   ```text
   /var/reports/audit.json.tmp.<pid>
   ```
2. Write all contents and flush to disk (`fsync`).
3. Atomically rename/replace the temp file to the final destination:
   ```python
   import os
   os.replace(temp_path, final_path)
   ```
4. This guarantees that external scripts reading the file will never observe a partially written or truncated payload.

### 4.2 Explicit Confirmation of Output Path
When writing to a file, always print the resolved absolute path to `stderr` upon completion:
```text
[+] Results successfully written to: /home/operator/reports/scan-20261022.json (14.2 KB)
```
