---
name: linux-cli-design-system
description: >-
  Comprehensive standard for architecture, terminal user experience, command design,
  output formatting, error handling, security, and quality assurance for Linux CLI tools
  (Ubuntu/Debian and compatible). Use this skill whenever designing, building, refactoring,
  reviewing, or testing command-line tools, developer utilities, security/pentesting tools,
  or system administration applications.
---

# Linux CLI Design System

The **Linux CLI Design System** provides an authoritative, reusable blueprint for developing professional, robust, and elegant command-line applications for Ubuntu and Linux distributions.

Every CLI tool built or reviewed under this system must be:
1. **Command-First**: Fully functional through standard CLI flags and subcommands; automation-ready.
2. **Terminal-Native & Respectful**: Clean visual hierarchy, consistent status prefixes, no visual noise, full `NO_COLOR` and terminal width compliance.
3. **Stream-Disciplined**: Strict separation of machine data (`stdout`) and human diagnostics/progress (`stderr`).
4. **Honest & Deterministic**: Zero fabricated metrics or faux progress; standard POSIX exit codes; clear errors with remedies.
5. **Secure & Portable**: Safe subprocess execution, credential redaction, least privilege, and adherence to Linux conventions (XDG base dirs, signal handling).

---

## 1. When to Apply This Skill

Activate this skill whenever you are:
- Designing a new Linux CLI utility from scratch.
- Adding commands or subcommands to an existing CLI tool.
- Refactoring terminal output, logs, or error handling.
- Adding machine-readable output formats (`--format json`, `--json`).
- Implementing interactive modes, spinners, or progress indicators.
- Auditing a CLI application for Linux standards, security, and UX quality.

---

## 2. Mandatory 7-Step Development Workflow

Whenever applying this skill to a project, follow these seven steps strictly:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MANDATORY WORKFLOW                              │
├───────────────┬────────────────────────────────────────────────────────┤
│ 1. Analyze    │ Purpose, target users, inputs, outputs, constraints    │
│ 2. Structure  │ Command hierarchy, subcommands, flags, defaults        │
│ 3. Standardize│ Terminal UX, color tokens, prefixes, table formatting  │
│ 4. Decouple   │ Domain logic isolated from rendering & I/O             │
│ 5. Implement  │ Respect existing codebase language & libraries         │
│ 6. Verify     │ Execute CLI tests (flags, pipes, signals, exit codes)  │
│ 7. Audit      │ Review against UX, QA, and Security checklists         │
└───────────────┴────────────────────────────────────────────────────────┘
```

### Step 1: Analyze the Tool Context
- Identify the primary operator profile (devops, secops, developer, automated cron/CI).
- Determine required data streams (interactive terminal vs piped into `jq`/`awk`/file).
- Check target Linux environment constraints (Ubuntu LTS, headless server, non-root user).
- **Rule**: CLI-first by default. Do not introduce a GUI, web dashboard, or Electron interface unless explicitly mandated by the user.

### Step 2: Define Command Architecture
- Design a predictable command tree: `tool [global-options] <subcommand> [flags] [arguments]`.
- Enforce standard flags: `-h/--help`, `-v/--version`, `-v/--verbose`, `-q/--quiet`, `-o/--output`, `--no-color`.
- Formulate sensible defaults so common operations run with minimal typing.
- Consult: [standards/command-design.md](standards/command-design.md).

### Step 3: Apply Visual & UX Standards
- Apply standard status prefixes: `[+]` Success, `[-]` Error, `[!]` Warning, `[*]` Info, `[?]` Prompt.
- Enforce terminal width wrapping and truncate overflow cleanly.
- Respect `NO_COLOR`, `TERM=dumb`, and non-TTY pipes.
- Consult: [standards/terminal-ux.md](standards/terminal-ux.md) & [patterns/status-and-colors.md](patterns/status-and-colors.md).

### Step 4: Decouple Architecture
- Isolate argument parsing (`cli/`), core execution (`core/`), formatting (`formatters/`), and OS adapters (`sys/`).
- Never bind business logic directly to `print()` or `fmt.Println()`.
- Consult: [standards/architecture.md](standards/architecture.md).

### Step 5: Implement Functionality
- Use the project's native language (Python, Go, Rust, Bash, C, Node.js).
- Leverage existing dependencies before adding new packages.
- Ensure safe process execution (no `shell=True` with user input).
- Consult: [standards/security.md](standards/security.md) & [standards/linux-portability.md](standards/linux-portability.md).

### Step 6: Verify Real Behavior
- Never claim tests pass without real execution.
- Validate: `--help`, exit codes, invalid inputs, SIGINT (Ctrl+C), non-TTY stdin redirection, JSON validity via `jq`.
- Consult: [checklists/implementation-qa.md](checklists/implementation-qa.md).

### Step 7: Audit & Polish
- Audit against the three quality checklists:
  - [checklists/cli-ux-review.md](checklists/cli-ux-review.md)
  - [checklists/implementation-qa.md](checklists/implementation-qa.md)
  - [checklists/security-audit.md](checklists/security-audit.md)

---

## 3. Skill Documentation Map

To keep workflows concise and token-efficient, detailed standards and implementation patterns are organized into modular reference files:

### Core Standards (`standards/`)
| Document | Focus & Content |
| :--- | :--- |
| [standards/terminal-ux.md](standards/terminal-ux.md) | Visual hierarchy, color tokens, status prefixes, tables, width compliance, minimal banners. |
| [standards/command-design.md](standards/command-design.md) | Command syntax, subcommands, flag conventions, validation, sensible defaults. |
| [standards/interactive-and-noninteractive.md](standards/interactive-and-noninteractive.md) | TTY detection, headless execution, prompt safety, `--yes`/`--force`, signal handling. |
| [standards/progress-and-lifecycle.md](standards/progress-and-lifecycle.md) | Honest state tracking, progress bars, spinners, stderr streaming, cancellation cleanup. |
| [standards/output-and-reporting.md](standards/output-and-reporting.md) | Stream separation (stdout vs stderr), JSON envelope schemas, file exports, atomic writes. |
| [standards/errors-logging-exitcodes.md](standards/errors-logging-exitcodes.md) | 3-part error anatomy, standard POSIX exit codes, logging levels, credential masking. |
| [standards/linux-portability.md](standards/linux-portability.md) | XDG Base Directory spec, Ubuntu compatibility, external dependency checks, shell pipes. |
| [standards/security.md](standards/security.md) | Subprocess security, path sanitization, credential protection, dry-run mode, privilege checks. |
| [standards/architecture.md](standards/architecture.md) | Modular layering, testable CLI design, configuration cascade (flags > env > file > defaults). |

### Concrete Patterns (`patterns/`)
| Document | Implementation Patterns & Code Examples |
| :--- | :--- |
| [patterns/help-screens.md](patterns/help-screens.md) | Standard layout template, syntax notation, option grouping, command examples. |
| [patterns/status-and-colors.md](patterns/status-and-colors.md) | ANSI escape sequences, color toggle implementations, no-color fallbacks. |
| [patterns/tables-and-formatting.md](patterns/tables-and-formatting.md) | Clean terminal tables, dynamic width calculation, key-value cards. |
| [patterns/progress-and-spinners.md](patterns/progress-and-spinners.md) | Terminal spinner loop, determinate progress bar, multi-stage pipelines. |
| [patterns/interactive-prompts.md](patterns/interactive-prompts.md) | Confirm prompts (`[y/N]`), masked password input, non-interactive bypass. |
| [patterns/structured-output-json.md](patterns/structured-output-json.md) | JSON envelope schema, NDJSON streaming, automated jq validation. |

### Quality & Review Checklists (`checklists/`)
| Document | Purpose |
| :--- | :--- |
| [checklists/cli-ux-review.md](checklists/cli-ux-review.md) | 20-point UX audit: prefixes, banners, width, colors, help readability. |
| [checklists/implementation-qa.md](checklists/implementation-qa.md) | Rigorous functional test matrix: flags, pipes, signals, exit codes. |
| [checklists/security-audit.md](checklists/security-audit.md) | Security checklist: argument injection, path traversal, permissions, secrets. |

---

## 4. Universal Design Rules (Quick Summary)

1. **Stdout is Sacred**: When JSON or machine output is requested, write *only* raw JSON to `stdout`. All logs, banners, progress, and warnings go to `stderr`.
2. **Never Fabricate**: Never show simulated progress, fake counts, or fabricated findings. If total items are unknown, use an indeterminate spinner, not a fake percentage.
3. **Color is Enhancing, Never Exclusive**: The user must understand all output even when ANSI colors are stripped (`NO_COLOR=1` or piped to a file).
4. **Actionable Errors**: Every error must say what failed, why it failed (if known), and what command or action will resolve it.
5. **No Blind Root**: Never require `sudo`/root unless strictly needed for raw sockets, kernel modules, or system files. Check `geteuid()` and explain why privileges are needed.
6. **Graceful Cancellation**: Catch `SIGINT` (Ctrl+C), clean up temporary files, kill child processes, and exit with code `130`. Never dump a raw stack trace to an end user.
