# Help Screen Patterns

This document provides reusable templates, layout conventions, and concrete examples for building intuitive terminal help documentation.

---

## 1. Help Screen Layout Template

A standard Linux CLI help screen is divided into logical sections separated by blank lines:

```text
Usage: <program> [GLOBAL-OPTIONS] <COMMAND> [OPTIONS] [ARGUMENTS]

<Brief description of tool purpose (1-2 sentences)>

Commands:
  <subcommand>       <Brief description of subcommand action>

Positional Arguments:
  <argument>         <Description of required/optional argument>

Options:
  <flags>            <Description and [default]>

Examples:
  <Concrete invocations with commentary>

Environment Variables:
  <ENV_VAR>          <Description and fallback>

Exit Codes:
  <Code>             <Meaning>
```

---

## 2. Syntax Notation Conventions

Adhere to standard POSIX syntax notations:
- **`UPPERCASE`** or **`<angle_brackets>`**: Mandatory placeholder value (e.g. `--target <HOST>`).
- **`[square_brackets]`**: Optional argument or flag (e.g. `[--timeout <sec>]`).
- **`...` (Ellipsis)**: Multiple values accepted (e.g. `<TARGET>...`).
- **`|` (Pipe)**: Mutually exclusive choices (e.g. `--format text|json|csv`).

---

## 3. Concrete Example: Subcommand Help Screen

```text
Usage: netpulse scan [OPTIONS] <TARGET>...

Scan one or more network targets for open ports, TLS configuration, and services.

Positional Arguments:
  <TARGET>...               One or more IP addresses, hostnames, or CIDR blocks

Scan Options:
  -p, --ports <PORTS>       Port list or range (e.g. '80,443' or '1-1024') [default: 1-1000]
  -s, --rate-limit <RPS>    Max packets per second [default: 500]
  -t, --timeout <SEC>       Connection timeout in seconds [default: 3.0]
      --dry-run             Simulate scan without transmitting network packets

Output Options:
  -f, --format <FORMAT>     Output format: text, json, csv [default: text]
  -o, --output <PATH>       Write output results to specified file path
  -q, --quiet               Suppress banner, status notices, and progress bars
      --no-color            Disable ANSI color escape sequences

Global Options:
  -v, --verbose             Increase diagnostic verbosity (-v for info, -vv for debug)
  -h, --help                Show this help message and exit

Examples:
  # Scan common web ports on a single host
  netpulse scan --ports 80,443,8080 192.168.1.10

  # Scan a /24 subnet and export raw JSON for automation
  netpulse scan --format json -o subnet.json 192.168.1.0/24

  # Perform a dry-run check against a domain
  netpulse scan --dry-run example.com

Exit Codes:
  0    All targets scanned successfully with no errors
  1    Scan failed due to host or network error
  2    Invalid arguments or unrecognized port syntax
  130  Scan aborted by user (SIGINT / Ctrl+C)
```
