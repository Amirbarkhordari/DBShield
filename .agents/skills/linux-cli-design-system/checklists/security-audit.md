# Security Audit Checklist

Use this checklist to perform an operational security and robustness review of any Linux CLI or system utility.

---

## 1. Process Execution & Subprocesses
- [ ] **No Shell Interpolation**: Subprocesses are invoked with explicit argument arrays (e.g. `["ping", "-c", "1", host]`).
- [ ] **No `shell=True` with Dynamic Strings**: Shell invocation with dynamic variables is strictly forbidden.
- [ ] **Argument Boundary `--`**: External tools receiving user-controlled paths or targets use `--` to prevent argument injection attacks.

---

## 2. Secrets & Credential Protection
- [ ] **No Secrets in CLI Flags**: Passwords and secret tokens are not passed via `--password` flags (preventing exposure in `/proc/<pid>/cmdline` and `ps aux`).
- [ ] **Stdin / Env Ingestion**: Secrets are ingested via environment variables, configuration files, or hidden standard input (`getpass`).
- [ ] **Log Scrubbing**: Log outputs, error messages, and debug traces automatically redact sensitive keys, tokens, and Authorization headers.
- [ ] **File Permissions**: Files storing credentials or tokens have permissions restricted to `0600` (`-rw-------`).

---

## 3. Filesystem Safety & Path Boundaries
- [ ] **Path Traversal Protection**: File inputs are resolved via canonical paths (`realpath`) and verified against intended base directories.
- [ ] **Atomic Writes**: Persistent output files are written to temporary files and atomically renamed to prevent file corruption during crashes.
- [ ] **Safe Temporary Files**: Temporary files use secure random generation (`mkstemp`, `tempfile`) inside `/tmp` or XDG directories to eliminate symlink race conditions (TOCTOU).

---

## 4. Privilege & Scope Control
- [ ] **Non-Root Operation**: Utility runs without root privileges whenever possible. Tasks like reading configs, help screens, and offline analysis never mandate root.
- [ ] **Target Scope Verification**: Pentesting and network scanning utilities validate targets against an authorized scope or subnet before transmitting packets.
- [ ] **Dry-Run Mode**: Destructive, mutating, or network-intensive operations support `--dry-run` to simulate actions safely.
- [ ] **Confirmation Guards**: High-risk actions (purging data, modifying firewall rules) require explicit confirmation unless bypassed with `--force` or `--yes`.
