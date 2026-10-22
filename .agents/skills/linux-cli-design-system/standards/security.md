# Security Standards for Linux CLI Tools

This document establishes the security guidelines for input sanitization, safe process execution, secret handling, least privilege, and scope containment in CLI applications and security utilities.

---

## 1. Safe Process Execution (Subprocess Injection Defense)

When wrapping system tools (such as `ip`, `iptables`, `nmap`, `curl`, `dig`):

### 1.1 Never Use Shell String Interpolation
- **CRITICAL**: Never invoke subshells with unsanitized string concatenation (e.g. `os.system("ping -c 1 " + user_target)` or Python `subprocess.run(f"ping {target}", shell=True)`).
- Passing inputs like `127.0.0.1; rm -rf /` or `127.0.0.1 $(whoami)` executes arbitrary attacker commands.

### 1.2 Always Pass Argument Lists
Execute binaries directly with an explicit list of separated arguments without a shell intermediary:

```python
# SECURE: Invokes execve directly with an array of arguments; no shell parsing
subprocess.run(["ping", "-c", "1", "--", target_ip], check=True, shell=False)

# INSECURE: Vulnerable to command injection
subprocess.run(f"ping -c 1 {target_ip}", shell=True)
```

---

## 2. Secrets and Credential Protection

### 2.1 The `/proc` Visibility Problem
On Linux, command-line arguments of any running process are readable by any local user on the machine via `ps aux`, `pstree`, or `/proc/<pid>/cmdline`.

### 2.2 Secure Ingestion Rules
1. **Never Accept Passwords as CLI Flags**:
   - Avoid `--password <secret>` flags on the command line.
   - Ingest sensitive tokens via:
     - Standard input prompt with disabled terminal echo (e.g. `getpass.getpass()`).
     - Standard input stream (`echo "$TOKEN" | tool login --token-stdin`).
     - Secure environment variables (e.g. `API_TOKEN`).
     - Secure configuration file with `0600` permissions (`~/.config/tool/credentials`).
2. **Scrub Memory Where Supported**:
   - In languages like C, Go, or Rust, zero out byte buffers containing sensitive cryptographic material before garbage collection or exit.

---

## 3. Path Traversal and Filesystem Boundaries

When a CLI accepts target filepaths or template paths from user arguments:

1. **Path Canonicalization**:
   - Resolve absolute paths using `os.path.realpath()` or `pathlib.Path.resolve()`.
2. **Boundary Validation**:
   - If writing files inside a workspace or export directory, verify that the canonical path resides within the intended base directory to prevent directory traversal (`../../etc/shadow`):
     ```python
     base_dir = os.path.realpath("/var/reports")
     target_path = os.path.realpath(os.path.join(base_dir, user_filename))
     if not target_path.startswith(base_dir + os.sep):
         raise SecurityError("Path traversal attempt detected.")
     ```

---

## 4. Scope Boundaries for Security & Pentesting Utilities

Security tools, vulnerability scanners, and network utilities carry operational risks of unintended targeting or denial-of-service.

### 4.1 Explicit Target Scope Verification
- Implement IP / CIDR scope guards: verify that scanned IP addresses fall within the operator-declared target scope.
- Warn or refuse to scan broadcast, multicast (`224.0.0.0/4`), or reserved loopback addresses unless explicitly allowed with `--allow-loopback`.

### 4.2 Dry-Run Mode (`--dry-run`, `-n`)
Support dry-run simulation for destructive or invasive actions:
```bash
# Validates targets, generates the payload, checks network route, but sends no packets:
firewall-rule-builder --add "DROP 10.0.0.5" --dry-run
```
Output:
```text
[*] [DRY RUN] Would execute: iptables -A INPUT -s 10.0.0.5 -j DROP
[*] [DRY RUN] No changes were applied to system state.
```

---

## 5. Non-Destructive Defaults and Confirmation Guards

1. **Default to Safety**: A missing argument must never trigger a mass-delete or full-subnet scan.
2. **Confirm Destructive Mutations**: Operations that delete databases, flush iptables, or modify system files must require interactive confirmation unless bypassed with `--force` or `--yes`.
