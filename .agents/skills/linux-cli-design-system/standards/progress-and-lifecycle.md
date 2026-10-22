# Progress and Operation Lifecycle Standards

This document specifies the rules for displaying task execution progress, spinners, activity indicators, operation summaries, and clean cancellation lifecycles.

---

## 1. The Honest State Principle

**The First Rule of CLI Progress:** *Never fabricate progress percentages, item counts, or completion states.*

1. **Zero Fake Progress**: If an operation takes an unknown amount of time (e.g. waiting for a network handshake, compiling a file, resolving DNS), **never** display an artificial progress bar that increments smoothly on a fake timer.
2. **Indeterminate Indicators for Unknown Totals**: When the total item count or completion time is indeterminate, use an activity spinner or simple item counter (`Processed 43 records... [Elapsed: 12s]`), never a percentage bar.
3. **Determinate Progress Only for Known Workloads**: A percentage progress bar (`[=======>    ] 70%`) is strictly reserved for operations where the total number of items, bytes, or steps is mathematically known in advance.

---

## 2. Stream Safety for Progress Indicators

Progress indicators, animated spinners, and live terminal updates must **never corrupt stdout**:

1. **Write Progress Exclusively to `stderr`**:
   - `stderr` is for human diagnostics and status monitoring.
   - `stdout` is reserved for actual payload data (especially when piped: `tool scan | jq`).
2. **Carriage Return `\r` Updates**:
   - Update progress lines using `\r` (carriage return) without a newline `\n`, allowing in-place redrawing.
3. **Clear on Exit**:
   - When the operation concludes, clear or overwrite the progress line before printing the final result or summary:
     ```text
     # Erase line sequence in ANSI: \r\033[K
     ```
4. **Suppress in Non-TTY / Batch Mode**:
   - If `stderr` is redirected to a file (`tool 2> err.log`) or run in CI (`CI=true`), do not emit carriage return animations. Instead, print discrete periodic milestones:
     ```text
     [*] [08:15:00] Batch 1/10 completed (100 items processed)
     [*] [08:15:30] Batch 2/10 completed (200 items processed)
     ```

---

## 3. Progress Indicator Types

### 3.1 Determinate Progress Bar (Known Workload)
Used for scanning a known IP subnet, downloading a file with `Content-Length`, or processing a known batch of files:

```text
Scanning subnet: [=====================>-------------] 65/100 (65%) | 12 it/s | ETA: 00:03
```
Components:
- Label describing active phase (`Scanning subnet:`)
- Visual bar using `=` and `>` (or UTF-8 `█` with ASCII fallback)
- Current count / Total count (`65/100`)
- Percentage (`65%`)
- Processing rate (`12 it/s` or `4.2 MB/s`)
- Estimated Time Remaining (`ETA: 00:03`)

### 3.2 Indeterminate Spinner (Unknown Workload)
Used for TLS handshakes, waiting for remote server startup, or unbounded crawler loops:

```text
[*] Probing target credentials... ⠋ [Elapsed: 00:04]
```
- Character frames: `⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏` (UTF-8) or `| / - \` (ASCII fallback).
- Includes elapsed time counter so the user knows the application is alive and not frozen.

---

## 4. Multi-Stage Operation Lifecycle

When a tool executes a sequential pipeline (e.g. `Resolve -> Discover -> Scan -> Report`):

```text
[*] Phase 1/4: Resolving DNS for 5 targets... [DONE]
[*] Phase 2/4: Discovering open ports...
    -> Host 10.0.0.1: [=============================] 1000/1000 ports [DONE]
    -> Host 10.0.0.2: [=============================] 1000/1000 ports [DONE]
[*] Phase 3/4: Fingerprinting service versions... [DONE]
[*] Phase 4/4: Generating output report... [DONE]
```

### Rules:
- Print clear milestone headers when transitioning between phases.
- If a sub-step fails, display the failure immediately without destroying previous log history:
  ```text
  [-] Phase 2/4: Target 10.0.0.3 timed out. Skipping host.
  ```

---

## 5. Controlled Cancellation & Resource Cleanup

When an operator presses `Ctrl+C` (SIGINT) or the process receives `SIGTERM`:

1. **Immediate Feedback**: Print `[!] Interrupt signal received. Cleaning up...` to `stderr`.
2. **Resource Teardown**:
   - Terminate active worker threads and child subprocesses.
   - Close active network sockets and database connections.
   - Delete partial, corrupted temporary files (`/tmp/audit-part-XXXX.tmp`).
   - If an output file was partially written, either remove it or rename it clearly (e.g. `report.partial.json`) so it is never mistaken for a complete result.
3. **Exit Code**: Always exit with code **130** (128 + SIGINT) on `Ctrl+C`.
