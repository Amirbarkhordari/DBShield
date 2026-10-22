# Project README Patterns

This document provides a comprehensive, production-grade `README.md` template optimized for Linux CLI utilities and software applications.

---

## 1. Master README Template

```markdown
# <Project Name>

<A concise 1-2 sentence elevator pitch explaining what the project does, its target audience, and key benefits.>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](#)

---

## Features

- **Feature 1**: Brief bullet describing primary capability.
- **Feature 2**: Brief bullet describing secondary capability.
- **Stream Discipline**: Clean JSON output (`--json`) separated from diagnostic progress (`stderr`).
- **Linux Native**: Full `NO_COLOR` compliance, standard exit codes, and XDG base directory support.

---

## Requirements

- **Operating System**: Ubuntu 22.04 LTS / 24.04 LTS or compatible Linux distribution.
- **Runtime**: Python 3.10+ / Go 1.22+ / Rust 1.75+.
- **External Dependencies**: `curl`, `iproute2` (if applicable).

---

## Installation

### From Source
```bash
git clone https://github.com/<owner>/<repo>.git
cd <repo>
pip install -e .
```

### Direct Binary Download
```bash
curl -sSL https://github.com/<owner>/<repo>/releases/latest/download/<binary> -o /usr/local/bin/<binary>
chmod +x /usr/local/bin/<binary>
```

---

## Quickstart

Run a basic scan with default settings:
```bash
<binary> scan --target 192.168.1.10
```

Pipe structured JSON directly into `jq`:
```bash
<binary> scan --target 192.168.1.0/24 --format json | jq '.data.findings[]'
```

---

## Command Reference

### Global Options
| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--help` | `-h` | Display usage information | — |
| `--version` | `-V` | Print version and build metadata | — |
| `--verbose` | `-v` | Enable diagnostic logging | `false` |
| `--quiet` | `-q` | Suppress non-essential output | `false` |
| `--no-color` | | Disable ANSI terminal escape codes | `false` |

### Subcommands
- **`scan`**: Execute target probing and service discovery.
- **`report`**: Generate HTML/JSON compliance summaries.
- **`config`**: Inspect or validate local configuration files.

---

## Configuration

Configuration values are resolved using the following precedence:
1. Command-line flags (e.g. `--timeout 15`)
2. Environment variables (e.g. `<TOOLNAME>_TIMEOUT=15`)
3. User configuration file (`~/.config/<tool>/config.toml`)
4. Default settings (timeout: 10s)

---

## Development & Testing

Run unit and integration tests:
```bash
pytest tests/ -v
```

Audit code style and typing:
```bash
ruff check .
mypy .
```

---

## Limitations

- Raw socket operations (`--driver raw`) require `CAP_NET_RAW` or `sudo`.
- Performance in virtualized environments may vary based on hypervisor network bridging.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
```
