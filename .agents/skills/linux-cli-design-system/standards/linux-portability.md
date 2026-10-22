# Linux Portability and System Standards

This document establishes guidelines for running seamlessly across Ubuntu and modern Linux environments, adhering to Linux filesystem standards, terminal emulators, and shell pipelines.

---

## 1. Linux Filesystem Standards (XDG Base Directory Spec)

Never dump configuration files, cached tokens, or database files directly into the root of `~` (`$HOME`). Strictly follow the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html):

| Directory Role | Standard Environment Variable | Default Fallback Path | Example Contents |
| :--- | :--- | :--- | :--- |
| **User Configuration** | `$XDG_CONFIG_HOME` | `~/.config/<tool>/` | `config.toml`, `settings.json`, credentials profiles |
| **Persistent Data** | `$XDG_DATA_HOME` | `~/.local/share/<tool>/` | SQLite databases, downloaded wordlists, history |
| **Cache Files** | `$XDG_CACHE_HOME` | `~/.cache/<tool>/` | Cached HTTP responses, temporary downloads |
| **State / Runtime Logs**| `$XDG_STATE_HOME` | `~/.local/state/<tool>/` | Session logs, command history |
| **System-wide Config** | `$XDG_CONFIG_DIRS` | `/etc/<tool>/` | Default baseline configuration for all users |

### 1.1 Secure Permissions on Created Files
- Config directories holding sensitive data (API keys, certificates): **`0700`** (`rwx------`).
- Sensitive credential files: **`0600`** (`rw-------`).
- Ensure directory creation explicitly sets secure umask/permissions:
  ```python
  import os
  os.makedirs(config_dir, mode=0o700, exist_ok=True)
  ```

---

## 2. External Dependency Management

If your CLI relies on system binaries (e.g. `nmap`, `iptables`, `ip`, `curl`, `dig`, `tcpdump`):

### 2.1 Pre-Flight Executable Check
Never fail deep inside an operation with a cryptic `FileNotFoundError` or `exec: "nmap": executable file not found in $PATH`. Check dependencies at startup:

```python
import shutil, sys

def require_dependency(binary_name: str, package_hint: str):
    if not shutil.which(binary_name):
        sys.stderr.write(
            f"[-] Error: Required system binary '{binary_name}' was not found in PATH.\n"
            f"    Remedy: Install it via apt: 'sudo apt update && sudo apt install {package_hint}'\n"
        )
        sys.exit(127)  # Exit code 127: Command not found
```

---

## 3. Terminal Environments and Character Encoding

Linux operators access CLI tools through diverse environments: SSH sessions, serial consoles, tmux multiplexers, Docker containers, and CI runners.

### 3.1 Encoding Detection and Fallback
- While modern Linux distributions use `UTF-8` locales (`en_US.UTF-8`), minimal Docker containers or remote consoles may run with `POSIX` or `C` locale.
- If the detected terminal encoding is not UTF-8:
  - Fall back from fancy Unicode symbols (`✔`, `✖`, `┌──┐`, `█`) to plain ASCII equivalents (`[+]`, `[-]`, `+--+`, `=`).
  - Never crash with `UnicodeEncodeError: 'ascii' codec can't encode character...`.

### 3.2 Terminal Dimensions (`SIGWINCH`)
- When formatting wide tables or drawing progress bars, query terminal columns dynamically (`shutil.get_terminal_size()`).
- In long-running interactive tools, listen for `SIGWINCH` signals to adjust layout when the operator resizes their terminal window.

---

## 4. Pipeline and Shell Integration

### 4.1 Stdin Piping Support
Allow tools to consume input either from command-line arguments or via piped `stdin`:
```bash
# Both of these should work identically:
tool scan --target 10.0.0.1
cat targets.txt | tool scan
```

### 4.2 Handling Downstream SIGPIPE
When piped to pagers or filter tools (e.g. `tool list | head -n 5`):
- `head` closes the pipe after 5 lines.
- The operating system sends `SIGPIPE` to `tool`.
- Handle `SIGPIPE` silently without printing a Python `BrokenPipeError` traceback to `stderr`. Exit with code `0` or `141`.
