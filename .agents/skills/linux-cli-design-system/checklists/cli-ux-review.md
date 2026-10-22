# CLI UX Review Checklist

Use this checklist to perform a terminal user experience review of any Linux CLI tool before release.

---

## 1. Visual Hierarchy & Status Feedback
- [ ] **Standard Prefixes**: Status lines use canonical prefixes: `[+]` Success, `[-]` Error, `[!]` Warning, `[*]` Info, `[?]` Prompt.
- [ ] **Color Accessibility**: Color enhances presentation but is not the sole transmitter of status. Every message is understandable with ANSI colors stripped.
- [ ] **`NO_COLOR` Compliance**: The tool disables all ANSI styling when `NO_COLOR` is present in the environment or `--no-color` is passed.
- [ ] **Terminal Width Awareness**: Tables and dividers dynamically respect terminal width (`COLUMNS` or standard library detection). No ragged row wrapping occurs at standard 80 columns.
- [ ] **Banners**: Startup banners are limited to at most 1–2 lines in interactive mode, and completely omitted in `--quiet`, `--json`, or non-TTY execution.

---

## 2. Help & Discoverability
- [ ] **Usage Screen**: `--help` / `-h` renders a clean, organized usage screen with grouped options.
- [ ] **Version Flag**: `--version` / `-V` prints tool version, commit hash, and build information.
- [ ] **Examples**: The help screen provides at least 2–3 copy-pasteable, realistic command examples.
- [ ] **Defaults Stated**: Every optional flag states its default value in its help description (e.g. `[default: 30]`).
- [ ] **Subcommand Help**: Every subcommand provides its own targeted help screen (e.g. `tool scan --help`).

---

## 3. Stream Discipline & Clean Piping
- [ ] **Stdout Purity**: When `--format json` or `--json` is active, `stdout` contains 100% valid JSON and zero ANSI codes, banners, or progress logs.
- [ ] **Stderr for Diagnostics**: All logs, spinners, progress bars, and operational warnings are directed strictly to `stderr`.
- [ ] **Pipe Readiness**: Piped invocations (e.g. `tool scan | jq .` or `tool list | grep foo`) execute cleanly without terminal corruption or crashes.
- [ ] **Quiet Mode**: The `-q` / `--quiet` flag suppresses all non-essential informational messages, outputting only critical results and errors.

---

## 4. Progress and State Honesty
- [ ] **No Fabricated Progress**: Progress bars are used only when the total workload is mathematically known.
- [ ] **Indeterminate Spinner**: Indeterminate spinners or simple counters are used when total duration/workload is unknown.
- [ ] **Cursor State Restoration**: Terminal cursor is never left invisible (`\033[?25h` is guaranteed to run even on exit or crash).
- [ ] **Execution Summary**: Multi-step operations conclude with a structured summary block showing counts, elapsed time, and output locations.
