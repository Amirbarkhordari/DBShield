# Interactive Prompt Patterns

This document provides reusable implementations for confirmation guards, default-value inputs, and hidden credential entry with automated non-interactive detection.

---

## 1. Confirmation Guard Pattern

Use this pattern before initiating destructive or irreversible system mutations:

```python
"""
prompts.py - Interactive prompts with non-interactive safety
"""
import sys
import getpass
from typing import Optional

def confirm(prompt_text: str, default: bool = False, force: bool = False) -> bool:
    """
    Prompt the user for [y/N] confirmation.
    
    If force is True, bypasses prompt and returns True.
    If stdin is not a TTY, aborts with an error to prevent hanging.
    """
    if force:
        return True

    if not sys.stdin.isatty():
        sys.stderr.write(
            "[-] Error: Confirmation required, but running in non-interactive environment.\n"
            "    Remedy: Pass '--yes' or '--force' to explicitly authorize this operation.\n"
        )
        sys.exit(2)

    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        sys.stderr.write(f"[?] {prompt_text}{suffix}")
        sys.stderr.flush()

        try:
            choice = sys.stdin.readline().strip().lower()
        except (KeyboardInterrupt, EOFError):
            sys.stderr.write("\n[!] Operation cancelled by user.\n")
            sys.exit(130)

        if not choice:
            return default
        if choice in ("y", "yes"):
            return True
        if choice in ("n", "no"):
            return False

        sys.stderr.write("    Please enter 'y' or 'n'.\n")
```

---

## 2. Text Input with Fallback Default

```python
def prompt_input(prompt_text: str, default: Optional[str] = None) -> str:
    """Prompt for text input with an optional default value."""
    if not sys.stdin.isatty():
        if default is not None:
            return default
        sys.stderr.write(f"[-] Error: Input '{prompt_text}' required but stdin is not a TTY.\n")
        sys.exit(2)

    suffix = f" [{default}]: " if default else ": "
    sys.stderr.write(f"[?] {prompt_text}{suffix}")
    sys.stderr.flush()

    try:
        val = sys.stdin.readline().strip()
    except (KeyboardInterrupt, EOFError):
        sys.stderr.write("\n[!] Operation cancelled.\n")
        sys.exit(130)

    return val if val else (default or "")
```

---

## 3. Masked Secret Input

When ingesting passwords or private tokens without leaking them to the screen or shell history:

```python
def prompt_secret(prompt_text: str = "Enter secret token") -> str:
    """Prompt for secret without echoing characters to the terminal."""
    if not sys.stdin.isatty():
        # In non-interactive mode, attempt reading directly from piped stdin
        secret = sys.stdin.readline().strip()
        if not secret:
            sys.stderr.write("[-] Error: Secret token was empty on stdin.\n")
            sys.exit(2)
        return secret

    try:
        return getpass.getpass(prompt=f"[?] {prompt_text}: ")
    except (KeyboardInterrupt, EOFError):
        sys.stderr.write("\n[!] Input cancelled.\n")
        sys.exit(130)
```
