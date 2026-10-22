# Progress Bars and Spinner Patterns

This document provides reusable implementations for indeterminate terminal spinners and determinate progress bars that strictly write to `stderr`, restore cursor state, and degrade gracefully in non-interactive environments.

---

## 1. Determinate Progress Bar Pattern

Use this pattern when the total number of items, bytes, or tasks is known in advance:

```python
"""
progress_bar.py - Stream-safe terminal progress bar
"""
import sys
import time
import shutil

class ProgressBar:
    def __init__(self, total: int, label: str = "Processing", bar_length: int = 25):
        self.total = max(1, total)
        self.current = 0
        self.label = label
        self.bar_length = bar_length
        self.start_time = time.time()
        self.is_tty = sys.stderr.isatty()
        self._last_print_time = 0.0

    def update(self, count: int = 1) -> None:
        self.current = min(self.total, self.current + count)
        now = time.time()

        # Throttle updates to 20Hz to prevent terminal flicker
        if self.current < self.total and (now - self._last_print_time) < 0.05:
            return

        self._last_print_time = now
        self._render()

    def _render(self) -> None:
        fraction = self.current / self.total
        percent = int(fraction * 100)
        filled = int(self.bar_length * fraction)
        bar = "=" * filled + (">" if filled < self.bar_length else "")
        bar = bar.ljust(self.bar_length, "-")

        elapsed = time.time() - self.start_time
        rate = self.current / elapsed if elapsed > 0 else 0.0

        if fraction > 0 and rate > 0:
            remaining_secs = max(0, int((self.total - self.current) / rate))
            eta_str = f"ETA: {remaining_secs // 60:02d}:{remaining_secs % 60:02d}"
        else:
            eta_str = "ETA: --:--"

        if self.is_tty:
            # Overwrite line with \r on stderr
            line = f"\r[*] {self.label}: [{bar}] {self.current}/{self.total} ({percent}%) | {rate:.1f} it/s | {eta_str}"
            sys.stderr.write(line)
            sys.stderr.flush()
        else:
            # Non-TTY: Print milestone updates every 25%
            if percent in (25, 50, 75, 100) and self.current >= int(self.total * (percent / 100)):
                sys.stderr.write(f"[*] {self.label}: {percent}% completed ({self.current}/{self.total})\n")
                sys.stderr.flush()

    def finish(self, message: str = "Done.") -> None:
        if self.is_tty:
            # Clear line and print final status
            sys.stderr.write(f"\r\033[K[+] {self.label}: Complete ({self.total}/{self.total}) - {message}\n")
        else:
            sys.stderr.write(f"[+] {self.label}: Complete - {message}\n")
        sys.stderr.flush()
```

---

## 2. Indeterminate Activity Spinner Pattern

Use this pattern when the total workload or duration is unknown (e.g. DNS lookups, TLS negotiations, remote API queries):

```python
"""
spinner.py - Background thread terminal spinner
"""
import sys
import time
import threading

class Spinner:
    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    ASCII_FRAMES = ["|", "/", "-", "\\"]

    def __init__(self, message: str = "Working"):
        self.message = message
        self.stop_event = threading.Event()
        self.thread = None
        self.is_tty = sys.stderr.isatty()
        self.start_time = 0.0

    def _spin(self) -> None:
        # Hide cursor
        sys.stderr.write("\033[?25l")
        sys.stderr.flush()

        idx = 0
        try:
            while not self.stop_event.is_set():
                elapsed = int(time.time() - self.start_time)
                frame = self.FRAMES[idx % len(self.FRAMES)]
                line = f"\r[*] {self.message}... {frame} [Elapsed: {elapsed // 60:02d}:{elapsed % 60:02d}]"
                sys.stderr.write(line)
                sys.stderr.flush()
                idx += 1
                time.sleep(0.08)
        finally:
            # Always restore cursor
            sys.stderr.write("\033[?25h")
            sys.stderr.flush()

    def start(self) -> None:
        self.start_time = time.time()
        if self.is_tty:
            self.thread = threading.Thread(target=self._spin, daemon=True)
            self.thread.start()
        else:
            sys.stderr.write(f"[*] {self.message}...\n")
            sys.stderr.flush()

    def stop(self, success: bool = True, final_text: str = "") -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join()

        elapsed = time.time() - self.start_time
        if self.is_tty:
            # Clear line
            sys.stderr.write("\r\033[K")

        prefix = "[+]" if success else "[-]"
        text = final_text or ("Completed" if success else "Failed")
        sys.stderr.write(f"{prefix} {self.message}: {text} ({elapsed:.2f}s)\n")
        sys.stderr.flush()
```
