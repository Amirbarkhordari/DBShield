# Architecture and Code Quality Standards

This document establishes the decoupled layered architecture for Linux CLI tools, enabling 100% testable core logic, multiple output formatters, and clean configuration precedence.

---

## 1. Decoupled 4-Layer Architecture

A well-architected CLI application separates presentation, CLI parsing, core domain logic, and operating system adapters.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        LAYER 1: CLI & PARSING                          │
│        (argparse / click / typer / cobra / clap / commander)           │
│  - Parses flags, validates input syntax, handles --help / --version    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Calls
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       LAYER 2: CORE DOMAIN LOGIC                       │
│  - Pure business logic: scanning, data calculation, business rules     │
│  - Emits pure data structures (dicts, structs, dataclasses)            │
│  - ZERO print() or terminal formatting calls inside this layer!         │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │ Returns data                   │ Invokes
                    ▼                                ▼
┌──────────────────────────────────────┐   ┌─────────────────────────────┐
│     LAYER 3: OUTPUT FORMATTERS       │   │    LAYER 4: I/O ADAPTERS    │
│  - Human Printer (tables, colors)    │   │  - Subprocess runner        │
│  - JSON Envelope Formatter           │   │  - Network / Socket client  │
│  - CSV / Plaintext Exporter          │   │  - Filesystem & XDG paths   │
└──────────────────────────────────────┘   └─────────────────────────────┘
```

### Why Decoupling is Essential:
1. **Unit Testing without Mocking Stderr/Stdout**: Core logic functions return pure data structures. Unit tests assert directly on data dictionaries or objects, without scraping terminal strings or regex-matching colored output.
2. **Pluggable Output**: Adding a new output format (e.g. Markdown report, SARIF, YAML) requires writing only a single formatter function, without modifying any business logic.
3. **Library Reusability**: The core package can be imported directly into other scripts, Python notebooks, or Go services as an internal library.

---

## 2. Directory Layout Recommendations

### 2.1 Python CLI Project Layout
```text
mytool/
├── pyproject.toml              # Packaging & dependencies
├── README.md
├── mytool/
│   ├── __init__.py
│   ├── cli.py                  # Entrypoint: argument parser & dispatch
│   ├── config.py               # XDG path resolution & config loader
│   ├── exceptions.py           # Custom typed exceptions with remedies
│   ├── core/                   # Pure business logic
│   │   ├── __init__.py
│   │   ├── scanner.py
│   │   └── models.py           # Dataclasses / Pydantic models
│   ├── formatters/             # Output rendering
│   │   ├── __init__.py
│   │   ├── human.py            # ANSI tables, prefixes, colors
│   │   └── json.py             # Stable envelope builder
│   └── adapters/               # System & network I/O
│       ├── __init__.py
│       └── system.py           # Safe subprocess execution & privileges
└── tests/
    ├── test_cli.py             # CLI flag & exit code tests
    ├── test_core.py            # Pure unit tests
    └── test_formatters.py      # JSON schema & human rendering tests
```

### 2.2 Go CLI Project Layout
```text
mytool/
├── go.mod
├── cmd/
│   └── mytool/
│       └── main.go             # Entrypoint & signal setup
├── internal/
│   ├── cli/                    # Cobra / flag commands
│   ├── config/                 # Viper / XDG configuration
│   ├── core/                   # Domain logic & models
│   ├── formatters/             # Table & JSON renderers
│   └── sys/                    # Process execution & signal handling
└── test/
    └── integration_test.go
```

---

## 3. Configuration Precedence Cascade

When an application supports configuration files, environment variables, and CLI flags, values must resolve according to the strict **precedence cascade**:

```
┌────────────────────────────────────────────────────────┐
│ 1. Explicit CLI Flags       (Highest precedence)       │
│    e.g. --timeout 30                                   │
├────────────────────────────────────────────────────────┤
│ 2. Environment Variables                               │
│    e.g. NETPULSE_TIMEOUT=20                            │
├────────────────────────────────────────────────────────┤
│ 3. Configuration File                                  │
│    e.g. ~/.config/netpulse/config.toml (timeout = 15)  │
├────────────────────────────────────────────────────────┤
│ 4. Hardcoded Application Defaults (Lowest precedence)  │
│    e.g. DEFAULT_TIMEOUT = 10                           │
└────────────────────────────────────────────────────────┘
```

### Rules:
- Explicit CLI arguments must **always** override environment variables and configuration files.
- Environment variables must use a consistent uppercase prefix matching the binary name: `TOOLNAME_<SETTING>` (e.g. `NETPULSE_OUTPUT_FORMAT`, `NETPULSE_API_KEY`).
