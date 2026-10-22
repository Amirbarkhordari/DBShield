# Command Design Standards

This document establishes the command syntax, flag naming conventions, argument validation patterns, and help documentation standards for Linux CLI tools.

---

## 1. Syntax & Command Hierarchy

Adhere to GNU/POSIX CLI command conventions:
```text
tool [global-options] <command> [subcommand] [command-options] [arguments]
```

### 1.1 Structural Taxonomy
1. **Tool / Binary**: The root executable (`netaudit`).
2. **Global Options**: Options modifying process-level behavior across all commands (`-v`, `--config <path>`, `--no-color`, `--quiet`).
3. **Subcommand / Action**: A noun or verb describing the specific domain operation (`scan`, `user add`, `report export`).
4. **Command Options**: Flags specific to the selected command (`--target 10.0.0.1`, `--ports 80,443`).
5. **Positional Arguments**: Required or primary operands (e.g. file paths, hostnames, identifiers).

### 1.2 Hierarchy Guidelines
- Use subcommands when a tool has multiple distinct operations or manages multiple resource types:
  ```text
  # Good: Clear hierarchical resources
  cloudctl cluster list
  cloudctl cluster create --name prod-01
  cloudctl node drain --node worker-3

  # Avoid: Flat bloated flag switches
  cloudctl --action create-cluster --cluster-name prod-01
  ```
- For single-purpose utilities (e.g. `fast-ping`, `hash-checker`), do not introduce unnecessary nested subcommands. Direct options and positional inputs are preferred:
  ```text
  hashcheck file.iso --algorithm sha256
  ```

---

## 2. Option & Flag Conventions

### 2.1 Standard Flag Names
Consistency across the toolchain reduces operator cognitive load. Always use these canonical flag names:

| Flag Name | Short | Description |
| :--- | :--- | :--- |
| `--help` | `-h` | Display detailed usage information and exit |
| `--version` | `-V` or `-v` | Display tool version, commit hash, and build date |
| `--verbose` | `-v` | Increase diagnostic output verbosity (can be stacked: `-vv`) |
| `--quiet` | `-q` | Suppress all informational banners and progress indicators |
| `--output <file>`| `-o` | Specify output file path |
| `--format <fmt>` | `-f` | Output format: `text` (default), `json`, `csv`, `yaml` |
| `--config <file>`| `-c` | Specify custom path to configuration file |
| `--timeout <sec>`| `-t` | Operation timeout in seconds |
| `--dry-run` | `-n` | Simulate operation without performing destructive mutations |
| `--force` | `-f` | Bypass interactive confirmation checks |
| `--yes` | `-y` | Automatically answer 'yes' to all confirmation prompts |
| `--no-color` | | Disable all ANSI color and text decoration escape sequences |

### 2.2 Flag Naming Rules
1. **Kebab-Case for Long Flags**: Always use lowercase words separated by hyphens (e.g., `--rate-limit`, `--max-retries`, `--api-key`). Never use camelCase (`--rateLimit`) or snake_case (`--rate_limit`).
2. **Conservative Short Flags**: Only assign single-character short flags to the most frequently typed options. Never invent cryptic short flags for rarely used settings.
3. **Double Dash `--` Sentinel**: Support standard `--` to terminate flag parsing and treat all following arguments as positional arguments (vital for passing file names starting with `-`).

---

## 3. Argument Validation & Fail-Fast Philosophy

Validate all user-supplied arguments **before** initiating network requests, database queries, or mutating filesystem state.

### Validation Checklist
- **Path Verification**: Does the target file exist? Is it readable/writable? Are directory permissions valid?
- **Port Ranges**: Is the port between 1 and 65535?
- **IP / CIDR / Domain**: Is the IP valid IPv4/IPv6? Is the domain syntactically correct?
- **Enum Values**: Does `--format` match one of `[text, json, csv]`? Reject unknown formats immediately.
- **Mutual Exclusivity**: Are mutually incompatible flags supplied together (e.g. `--quiet` and `--verbose`, or `--all` and `--id 123`)?

### Fail-Fast Error Message
If validation fails, exit immediately with exit code `2` (usage error), print a targeted explanation, and suggest the correct flag:
```text
[-] Error: Invalid port range '70000'. Port numbers must be between 1 and 65535.
    Try 'netaudit scan --help' for usage examples.
```

---

## 4. Sensible Defaults

1. **Safe by Default**: Default to non-destructive actions. Default to standard, safe timeout limits (e.g. 10s or 30s) rather than indefinite hangs.
2. **Zero-Configuration Operation**: Whenever possible, ensure running `tool <subcommand>` without arguments provides either a safe default behavior or clear help.
3. **Explicit Documentation**: Every default value must be explicitly stated in the help text:
   ```text
   --concurrency <N>     Number of parallel scan threads [default: 10]
   --timeout <sec>       Connection timeout in seconds [default: 5.0]
   ```

---

## 5. Help Screen Standard Layout

Help screens must be self-contained, beautifully formatted, and include concrete, copy-pasteable examples.

### Help Template Structure
```text
Usage: <binary> [GLOBAL OPTIONS] <COMMAND> [OPTIONS] [ARGUMENTS]

<One-sentence concise description of what the tool does>

Commands:
  scan          Run port and service discovery against target
  report        Generate compliance and vulnerability reports
  config        Manage and inspect local tool settings

Global Options:
  -c, --config <FILE>       Path to config file [default: ~/.config/tool/config.toml]
  -v, --verbose             Enable detailed debug logs
  -q, --quiet               Suppress informational banners and progress
      --no-color            Disable colored terminal output
  -h, --help                Show this help message and exit
  -V, --version             Print version information and exit

Examples:
  # Scan a single host with default options
  tool scan --target 192.168.1.1

  # Scan a subnet, outputting results directly to JSON
  tool scan --target 192.168.1.0/24 --format json -o subnet.json

  # Run in dry-run mode to verify targets without sending packets
  tool scan --target targets.txt --dry-run
```
