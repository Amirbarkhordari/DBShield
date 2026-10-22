# Status Prefixes and Color Patterns

This document provides reusable implementations and code patterns for terminal color tokens, status prefixes, and automated color suppression.

---

## 1. Status Prefix Reference

Every status message must start with a standardized 3-character prefix:

```text
[+] Success   (ANSI Green:   \033[1;32m)
[-] Error     (ANSI Red:     \033[1;31m)
[!] Warning   (ANSI Yellow:  \033[1;33m)
[*] Info      (ANSI Cyan:    \033[1;36m)
[?] Prompt    (ANSI Magenta: \033[1;35m)
[~] Debug     (ANSI Gray:    \033[90m)
```

---

## 2. Reusable Python Implementation

This production-grade Python module handles color detection, `NO_COLOR` compliance, non-TTY detection, and prefix formatting:

```python
"""
terminal_ui.py - Reusable terminal UI helper
"""
import os
import sys

class TerminalUI:
    # ANSI escape codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"
    
    BOLD_RED = "\033[1;31m"
    BOLD_GREEN = "\033[1;32m"
    BOLD_YELLOW = "\033[1;33m"
    BOLD_CYAN = "\033[1;36m"
    BOLD_MAGENTA = "\033[1;35m"

    def __init__(self, force_color: bool = False, no_color: bool = False):
        self.enabled = self._should_enable_color(force_color, no_color)

    def _should_enable_color(self, force_color: bool, no_color: bool) -> bool:
        if no_color or "NO_COLOR" in os.environ:
            return False
        if force_color:
            return True
        if os.environ.get("TERM") == "dumb":
            return False
        # Enable color only if stderr is a live TTY
        return sys.stderr.isatty()

    def style(self, text: str, ansi_code: str) -> str:
        """Apply ANSI style if colors are enabled."""
        if not self.enabled:
            return text
        return f"{ansi_code}{text}{self.RESET}"

    # Status prefix formatters (written to stderr)
    def success(self, msg: str) -> None:
        prefix = self.style("[+]", self.BOLD_GREEN)
        sys.stderr.write(f"{prefix} {msg}\n")
        sys.stderr.flush()

    def error(self, msg: str, cause: str = None, remedy: str = None) -> None:
        prefix = self.style("[-]", self.BOLD_RED)
        sys.stderr.write(f"{prefix} Error: {msg}\n")
        if cause:
            sys.stderr.write(f"    Cause: {cause}\n")
        if remedy:
            sys.stderr.write(f"    Remedy: {remedy}\n")
        sys.stderr.flush()

    def warning(self, msg: str) -> None:
        prefix = self.style("[!]", self.BOLD_YELLOW)
        sys.stderr.write(f"{prefix} {msg}\n")
        sys.stderr.flush()

    def info(self, msg: str) -> None:
        prefix = self.style("[*]", self.BOLD_CYAN)
        sys.stderr.write(f"{prefix} {msg}\n")
        sys.stderr.flush()

    def debug(self, msg: str) -> None:
        prefix = self.style("[~]", self.GRAY)
        sys.stderr.write(f"{prefix} {msg}\n")
        sys.stderr.flush()
```

---

## 3. Reusable Bash Implementation

For shell scripts and lightweight Bash CLI wrappers:

```bash
#!/usr/bin/env bash
# colors.sh - Standard Linux CLI color & prefix helpers

# Detect whether color should be active
if [[ -n "${NO_COLOR:-}" || "$TERM" == "dumb" || ! -t 2 ]]; then
    COLOR_RESET=""
    COLOR_GREEN=""
    COLOR_RED=""
    COLOR_YELLOW=""
    COLOR_CYAN=""
else
    COLOR_RESET=$'\033[0m'
    COLOR_GREEN=$'\033[1;32m'
    COLOR_RED=$'\033[1;31m'
    COLOR_YELLOW=$'\033[1;33m'
    COLOR_CYAN=$'\033[1;36m'
fi

log_success() { printf "%s[+]%s %s\n" "$COLOR_GREEN"  "$COLOR_RESET" "$1" >&2; }
log_error()   { printf "%s[-]%s Error: %s\n" "$COLOR_RED"    "$COLOR_RESET" "$1" >&2; }
log_warn()    { printf "%s[!]%s Warning: %s\n" "$COLOR_YELLOW" "$COLOR_RESET" "$1" >&2; }
log_info()    { printf "%s[*]%s %s\n" "$COLOR_CYAN"   "$COLOR_RESET" "$1" >&2; }
```
