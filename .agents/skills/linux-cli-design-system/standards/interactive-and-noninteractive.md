# Interactive and Non-Interactive Modes

This document sets the operational standards for interactive user experiences, headless automation, TTY detection, signal management, and process privileges.

---

## 1. Command-First Principle

A command-line tool must be built **command-first**:
1. **Full Automation**: Every single feature, option, configuration choice, and action must be executable using CLI flags alone, without requiring interactive human input.
2. **Interactive Menus Are Optional**: Interactive wizards or curses/TUI menus may exist as an optional user-facing convenience, but they must **never** replace flag-driven operation.
3. **No Interactive Traps**: Never prompt for input when the required parameters can be passed via arguments.

---

## 2. TTY Detection & Automation Discipline

The tool must dynamically detect its operating environment before attempting to read interactive input or format rich output.

### 2.1 TTY Check Matrix
| Stream | Condition | Behavior |
| :--- | :--- | :--- |
| `stdin` is not a TTY | Piped input (e.g. `cat targets.txt \| tool scan`) or run in CI/cron | Do **not** show interactive prompts. Read data from `stdin` or fail immediately if a required argument is missing. |
| `stdout` is not a TTY | Output redirected (`tool scan > out.txt`) or piped (`tool scan \| jq .`) | Strip all ANSI colors. Do not print spinners or progress bars to `stdout`. |
| `stderr` is not a TTY | Diagnostics redirected (`tool 2> error.log`) | Strip ANSI colors from error and warning messages. |

### 2.2 Handling Missing Input in Non-Interactive Mode
If an interactive prompt would normally ask the user for confirmation or missing credentials, but `stdin` is not a TTY:
- **Do not hang indefinitely waiting for EOF.**
- Abort immediately with exit code `2` or `1`:
  ```text
  [-] Error: Missing required parameter '--target'.
      Interactive input is not supported in non-interactive / headless mode.
      Pass '--target <value>' or see '--help'.
  ```

---

## 3. Interactive Prompts & Confirmation Guards

### 3.1 Confirmation Prompts for Destructive Actions
Any action that deletes data, alters system firewall rules, kills processes, or mutates persistent infrastructure must require explicit confirmation when running interactively:

```text
[?] WARNING: This will purge all 42 cached records from /var/lib/netpulse.
    Are you sure you want to proceed? [y/N]: 
```

### 3.2 Standard Prompt Formatting
- Default to the safest action. Indicate default with an uppercase letter: `[y/N]` (default No) or `[Y/n]` (default Yes).
- Pressing `Enter` without typing input selects the default option.
- Accept `y`, `Y`, `yes`, `YES` as confirmation; anything else defaults to abort.

### 3.3 Prompt Bypassing (`--yes`, `--force`)
Automated scripts must be able to bypass confirmation prompts cleanly:
- Support `--yes` / `-y` to automatically affirm prompts.
- Support `--force` / `-f` to override confirmation checks for destructive commands.

---

## 4. Signal Handling & Clean Process Termination

Linux CLI applications must catch system signals and terminate gracefully without leaving corrupted files, orphaned child processes, or broken terminal modes.

### 4.1 Required Signal Handlers
| Signal | Event | Action Required |
| :--- | :--- | :--- |
| **SIGINT** (`Ctrl+C`) | User interrupts operation | Terminate ongoing tasks, clean up temp files, reset terminal cursor/raw mode, print `[!] Operation cancelled by user.` to `stderr`, and exit with **code 130**. |
| **SIGTERM** (`kill <pid>`) | OS or systemd requests shutdown | Gracefully flush buffers, release file locks, close sockets, and exit cleanly with **code 143**. |
| **SIGPIPE** | Pipe closed downstream (`tool \| head -n 5`) | Handle broken pipe quietly without printing raw Python `BrokenPipeError` traceback. Exit with **code 0** or `141`. |

### 4.2 Terminal State Restoration
If the CLI temporarily modifies terminal attributes (such as hiding the cursor with `\033[?25l` for a spinner, or putting the terminal in raw mode for keyboard shortcuts):
- Register an `atexit` or signal handler to **always restore the cursor** (`\033[?25h`) and reset terminal modes.
- Failure to restore the cursor leaves the user's terminal invisible and broken upon exit.

---

## 5. Privileged Operations & Least Privilege

System administration and network security tools often require elevated privileges (e.g. raw packet sockets, `iptables`, kernel tracing).

### 5.1 Root Privilege Verification Rules
1. **Never Require Root for Non-Privileged Tasks**:
   - Commands like `--help`, `--version`, configuration linting, offline report generation, and reading user-owned log files must **never** require root.
2. **Explicit Privilege Check**:
   - Check user privileges (`geteuid() == 0`) only when executing an action that genuinely requires it.
3. **Actionable Permission Denial Messages**:
   - If elevated privilege is required, explain *why* and give the exact command to run:
     ```text
     [-] Error: Raw socket creation requires elevated privileges (CAP_NET_RAW).
         Please rerun using: sudo netaudit scan --target 10.0.0.1
     ```
4. **Privilege Dropping**:
   - If a daemon or long-running utility is started as root to bind low ports (e.g. port 80/443), drop privileges to an unprivileged user (`nobody` or a dedicated service user) immediately after binding.
