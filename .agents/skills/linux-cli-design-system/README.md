# Linux CLI Design System Skill

A standardized architecture, terminal user experience, command design, output formatting, error handling, security, and quality assurance framework for Linux CLI tools targeting Ubuntu and Linux distributions.

---

## Directory Structure

```text
linux-cli-design-system/
├── SKILL.md                          # Antigravity skill definition & mandatory workflow
├── README.md                         # Architecture overview & index
├── standards/                        # Core authoritative standards
│   ├── terminal-ux.md                # Colors, prefixes, tables, width, banners
│   ├── command-design.md             # Syntax, subcommands, flags, defaults, validation
│   ├── interactive-and-noninteractive.md # TTY detection, headless automation, signals
│   ├── progress-and-lifecycle.md     # Honest progress bars, spinners, stderr streaming
│   ├── output-and-reporting.md       # Stream separation, JSON envelopes, atomic files
│   ├── errors-logging-exitcodes.md   # 3-part errors, POSIX exit codes, redaction
│   ├── linux-portability.md          # XDG directories, dependencies, Ubuntu compatibility
│   ├── security.md                   # Safe subprocesses, secrets, path sanitization
│   └── architecture.md               # 4-layer decoupled architecture & config cascade
├── patterns/                         # Reusable implementation templates
│   ├── help-screens.md               # Help layout & POSIX syntax patterns
│   ├── status-and-colors.md          # Python & Bash ANSI prefix formatters
│   ├── tables-and-formatting.md      # Auto-sizing table & key-value record renderers
│   ├── progress-and-spinners.md      # Stream-safe progress bar & thread spinner
│   ├── interactive-prompts.md        # [y/N] confirm guards & masked secret inputs
│   └── structured-output-json.md     # JSON envelope builder & NDJSON streaming
└── checklists/                       # Quality verification checklists
    ├── cli-ux-review.md              # 20-point visual & UX review
    ├── implementation-qa.md          # 14-point functional test matrix & exit codes
    └── security-audit.md             # Security, privilege & sanitization audit
```

---

## How to Apply in Future Projects

### 1. Automatic Discovery (Global)
Because this skill is installed into your Antigravity global configuration directory:
`~/.gemini/config/skills/linux-cli-design-system/`

The agent will automatically discover it across all projects on your system whenever you prompt for CLI development, refactoring, or auditing.

### 2. Workspace Version Control
You can also commit the `.agents/skills/linux-cli-design-system/` folder directly to any Git repository to ensure consistent CLI standards across your engineering team.
