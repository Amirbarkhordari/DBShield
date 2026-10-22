# Project Configuration Patterns (`.git-workflow.json`)

This document defines the schema, default behaviors, and isolation rules for the per-project configuration file `.git-workflow.json`.

---

## 1. Project Isolation Guarantee

Every software project and repository must be strictly isolated:
- **No Shared Remotes**: Project A must never inherit or push to Project B's repository URL.
- **No Shared Branches**: Project-specific branching models (e.g. `main` vs `trunk` vs `develop`) are kept distinct.
- **Local Precedence**: Local `.git-workflow.json` values always override generic global defaults.

---

## 2. Configuration Schema & Example

Place `.git-workflow.json` at the root of your project:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "project_name": "netpulse",
  "remote_name": "origin",
  "target_branch": "main",
  "auto_commit": true,
  "auto_push": false,
  "test_command": "pytest -v",
  "docs": {
    "readme": "README.md",
    "changelog": "CHANGELOG.md",
    "contributing": "CONTRIBUTING.md",
    "docs_dir": "docs"
  },
  "secret_scanning": {
    "enabled": true,
    "block_on_detect": true,
    "custom_patterns": []
  },
  "release": {
    "version_file": "pyproject.toml",
    "tag_prefix": "v",
    "require_clean_tree": true
  }
}
```

---

## 3. Field Definitions & Default Fallbacks

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `remote_name` | `string` | `"origin"` | Git remote alias configured for this repository. |
| `target_branch` | `string` | `"main"` | Default branch for local development and synchronization. |
| `auto_commit` | `boolean` | `true` | When true, automatically creates local Conventional Commits for verified tasks. |
| `auto_push` | `boolean` | `false` | When true, pushes committed changes to remote after verification. |
| `test_command` | `string` | `""` (auto-detect) | Shell command to execute project test suite before committing. |
| `docs.readme` | `string` | `"README.md"` | Path to primary project overview document. |
| `docs.changelog` | `string` | `"CHANGELOG.md"` | Path to project changelog. |
| `docs.contributing`| `string` | `"CONTRIBUTING.md"`| Path to contributor guidelines. |
| `docs.docs_dir` | `string` | `"docs"` | Directory for technical sub-documentation. |
| `secret_scanning.enabled` | `boolean` | `true` | Run pre-commit pattern scan for leaked credentials. |
| `secret_scanning.block_on_detect` | `boolean` | `true` | Immediately halt execution if any secret pattern matches. |
| `release.version_file` | `string` | `""` | File containing authoritative semantic version string. |
| `release.tag_prefix` | `string` | `"v"` | Prefix for Git tags (e.g. `v1.0.0`). |

---

## 4. Test Command Auto-Detection

If `test_command` is empty, the workflow inspects repository files to determine the test runner:

| Project Indicator | Auto-Detected Command |
| :--- | :--- |
| `pyproject.toml` or `pytest.ini` or `tests/` (Python) | `pytest` |
| `go.mod` (Go) | `go test ./...` |
| `Cargo.toml` (Rust) | `cargo test` |
| `package.json` with `"test"` script (Node.js) | `npm test` |
| `Makefile` with `test` target | `make test` |
