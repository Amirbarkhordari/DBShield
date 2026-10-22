# Terminal UX and Visual Standards

This document specifies the visual hierarchy, color conventions, formatting rules, and terminal ergonomics for Linux CLI tools.

---

## 1. Visual Hierarchy and Formatting

Terminal space is constrained. Every character printed should serve a clear communication purpose.

### 1.1 Status Prefixes

Use consistent, bracketed 3-character prefixes for status line items:

| Prefix | Color | Meaning | Usage |
| :--- | :--- | :--- | :--- |
| `[+]` | **Bold Green** | Success / Positive outcome | Target discovered, port open, service started, task finished |
| `[-]` | **Bold Red** | Error / Critical failure | Connection refused, host unreachable, file not found |
| `[!]` | **Bold Yellow** | Warning / Alert | Deprecated feature, high memory usage, potential risk, retry |
| `[*]` | **Bold Cyan/Blue** | Information / Notice | Configuration loaded, step starting, summary detail |
| `[?]` | **Bold Magenta** | Prompt / Question | Awaiting interactive user confirmation or input |
| `[~]` | **Dim Gray** | Verbose / Debug | Internal state, packet counts, trace output (only with `-v`) |

#### Text Representation Example
```text
[*] Starting scan on target 192.168.1.50:443 (TLS)
[+] TLS Certificate valid until 2027-04-15
[!] Weak cipher suite detected: TLS_RSA_WITH_AES_128_CBC_SHA
[-] Vulnerability detected: CVE-2024-XXXX (Critical)
[+] Scan complete. 1 issue found.
```

---

## 2. Color Standards & Accessibility

### 2.1 Standard Palette (ANSI 16 / 256 Colors)
To ensure readability across light and dark Linux terminal color schemes (Gnome Terminal, Alacritty, Kitty, Windows Terminal, xterm):

- **Success**: ANSI Green (`\033[32m`) or Bold Green (`\033[1;32m`).
- **Error**: ANSI Red (`\033[31m`) or Bold Red (`\033[1;31m`).
- **Warning**: ANSI Yellow (`\033[33m`) or Bold Yellow (`\033[1;33m`).
- **Info**: ANSI Cyan (`\033[36m`) or Blue (`\033[34m`).
- **Prompt**: ANSI Magenta (`\033[35m`).
- **Muted / Secondary**: ANSI Dim / Gray (`\033[2m` or `\033[90m`).
- **Headings / Emphasized**: ANSI Bold (`\033[1m`).
- **Reset**: `\033[0m`.

### 2.2 Color Independence (Non-Color Clarity)
Color must be an **enhancement**, never the sole transmitter of critical information:
- Never rely on colored text alone without a textual indicator.
  - **Wrong**: `status: healthy` (in green) vs `status: failed` (in red) where a colorblind user or stripped ANSI terminal cannot distinguish if the words were identical.
  - **Right**: `[+] Status: Healthy` vs `[-] Status: Failed`.
- Prefixes like `[+]`, `[-]`, and `[!]` ensure immediate clarity in monochrome environments, serial consoles, and plain log files.

### 2.3 Strict Color Suppression Rules
CLI applications must automatically disable ANSI colors under any of these conditions:
1. Environment variable `NO_COLOR` is set (regardless of its value, per [no-color.org](https://no-color.org)).
2. Environment variable `TERM=dumb`.
3. Output stream (`stdout` or `stderr`) is not a TTY (e.g. redirected to a file or piped into another program: `tool | grep foo`), unless forced via `--color=always`.
4. Command line flag `--no-color` is passed.

---

## 3. Terminal Banners and ASCII Art

Excessive ASCII art, cartoon logos, and sprawling multiline banners clutter the terminal, break scrollback history, and pollute log files.

### Rules for Banners
1. **Never print banners when non-interactive**: If `stdout` is not a TTY or `--json`/`--quiet` is active, zero banner text may be emitted.
2. **Compact Banners Only**: If a header is shown in human interactive mode, keep it to at most 1–2 lines:
   ```text
   NetPulse v2.4.0 — Linux Network Diagnostics & Security Scanner
   ```
3. **No Flashing / Animated Banners**: Never block execution or wait for banner animations before starting actual work.
4. **Quiet Flag (`-q`, `--quiet`)**: Must suppress all non-essential output, leaving only results and critical errors.

---

## 4. Tables and Layout Disciplines

### 4.1 Width Compliance
- Check terminal width dynamically (e.g. `COLUMNS` env var, `ioctl TIOCGWINSZ`, or standard library utilities like `os.get_terminal_size()`).
- Default to **80 columns** if width cannot be detected (such as when run in non-TTY or background pipes).
- Truncate long strings (e.g., URLs, SHA256 hashes, descriptions) with an ellipsis (`...`) rather than wrapping raggedly across rows.

### 4.2 Clean Border Styling
Prefer lightweight Unicode box drawing characters when UTF-8 is supported, with automatic ASCII fallback:

```text
# UTF-8 Mode:
┌──────┬──────────────┬──────────────┬─────────┐
│ ID   │ TARGET       │ STATUS       │ LATENCY │
├──────┼──────────────┼──────────────┼─────────┤
│ 001  │ 10.0.0.1     │ [+] Active   │ 1.2ms   │
│ 002  │ 10.0.0.2     │ [-] Timeout  │ —       │
└──────┴──────────────┴──────────────┴─────────┘

# ASCII Fallback (TERM=dumb or non-UTF8):
+------+--------------+--------------+---------+
| ID   | TARGET       | STATUS       | LATENCY |
+------+--------------+--------------+---------+
| 001  | 10.0.0.1     | [+] Active   | 1.2ms   |
| 002  | 10.0.0.2     | [-] Timeout  | -       |
+------+--------------+--------------+---------+
```

### 4.3 Key-Value Record View
When displaying a single entity or detailed report with many fields, use aligned key-value blocks instead of a single-row wide table:

```text
Target Details:
  Host:            scanme.example.com
  IP Address:      192.0.2.42
  State:           Up (0.42s latency)
  Open Ports:      22/tcp, 80/tcp, 443/tcp
  OS Detection:    Ubuntu Linux 24.04 (Linux 6.8)
  Last Seen:       2026-10-22 08:00:00 UTC
```

---

## 5. Summary Blocks

Long-running operations must conclude with a concise, formatted summary block:

```text
================================================================================
EXECUTION SUMMARY
================================================================================
  Targets Scanned:      128
  Successful Probes:    124
  Failures / Errors:    4
  Elapsed Time:         00:02:14.38
  Output Artifact:      /var/log/audit-2026-10-22.json
================================================================================
```
