---
name: git-workflow-and-project-docs
description: >-
  Standardized automation system for change tracking, conventional commits, GitHub
  synchronization, and project documentation lifecycle across software projects and Linux CLI tools.
  Use this skill whenever developing features, refactoring, fixing bugs, updating documentation,
  creating commits, managing releases, or syncing repositories with GitHub.
---

# Git Workflow & Project Documentation System

The **Git Workflow & Project Documentation System** (`git-workflow-and-project-docs`) provides an automated, secure, and disciplined development lifecycle for software projects and Linux CLI tools.

It guarantees that:
1. **Meaningful Changes Are Grouped & Committed**: Work is organized into logical, Conventional Commits—never blind batch dumps or keystroke-level noise.
2. **Project Documentation Evolves with Code**: `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, and technical subdocs are updated alongside code changes in the same atomic commit.
3. **GitHub Sync is Safe & Deterministic**: Clean remote verification, divergence detection, and safe pushes without risking history overwrites or force-pushes.
4. **Security & Secrets are Guarded**: Pre-commit secret scanning halts execution before sensitive tokens or credentials can ever be staged.
5. **Projects Remain Isolated**: Per-project configuration (`.git-workflow.json`) ensures no project inherits another repository's remote, branch, or credentials.

---

## 1. When to Apply This Skill

Activate this skill when:
- Starting or initializing a new software project or CLI repository.
- Completing a development task (feature, bugfix, refactoring, tests) that needs to be committed.
- Updating documentation to match new code, flags, or configuration.
- Syncing verified commits with a GitHub remote repository.
- Preparing a semantic release or maintaining `CHANGELOG.md`.
- Reviewing Git status, working tree diffs, and repository hygiene.

---

## 2. Mandatory 6-Phase Development Lifecycle

Whenever developing in a repository under this skill, follow these six phases:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   MANDATORY GIT & DOCS LIFECYCLE                       │
├───────────────┬────────────────────────────────────────────────────────┤
│ 1. Inspect    │ Git status, branch, remotes, diff, untracked files     │
│ 2. Document   │ Update README, CHANGELOG, and docs/ to match changes   │
│ 3. Validate   │ Run project test suite, linting, and quality checks    │
│ 4. Scan       │ Check diff for secrets, private keys, tokens, .env     │
│ 5. Commit     │ Stage specific files & commit with Conventional Commit │
│ 6. Synchronize│ Fetch remote, check divergence, push to target branch  │
└───────────────┴────────────────────────────────────────────────────────┘
```

### Phase 1: Inspect Repository State (Before Any Mutation)
1. Verify if the directory is a Git repository: `git rev-parse --is-inside-work-tree`.
   - If not, and the project is ready for version control, initialize it (`git init -b main`) and create a standard `.gitignore`.
2. Inspect the working tree: `git status --short --branch`.
3. Check configured remotes: `git remote -v`.
4. Inspect diff of current changes: `git diff` (unstaged) and `git diff --cached` (staged).
5. Identify any pre-existing user changes: **Never overwrite, reset, or silently commit unrelated user edits.**
6. Consult: [standards/commit-policy.md](standards/commit-policy.md).

### Phase 2: Synchronize Project Documentation
1. Identify all user-facing changes: new flags, modified behavior, renamed commands, changed defaults, new dependencies.
2. Update the affected sections in `README.md` (CLI syntax, examples, options table).
3. Append a bulleted entry in `CHANGELOG.md` under `## [Unreleased]` (sections: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`).
4. Update technical docs in `docs/` if architecture, protocols, or schema changed.
5. Consult: [standards/documentation-policy.md](standards/documentation-policy.md) & [patterns/changelog.md](patterns/changelog.md).

### Phase 3: Validate Quality & Run Tests
1. Read project test configuration from `.git-workflow.json` or detect from project files (`pytest`, `go test ./...`, `cargo test`, `npm test`).
2. Run test suite: all tests must pass before committing.
3. If tests fail, **halt the commit immediately**, report the error, and fix the defect.

### Phase 4: Security & Secret Scan
1. Inspect the exact diff of all files to be staged: `git diff <file>`.
2. Check against secret patterns: private keys, JWTs, API tokens (`ghp_`, `gho_`, `AKIA...`), passwords, credentials files (`.env`, `*.pem`, `id_rsa`).
3. If secrets or sensitive tokens are detected: **Halt immediately!** Alert the operator with remediation steps.
4. Consult: [standards/security-checks.md](standards/security-checks.md).

### Phase 5: Create Local Conventional Commit
1. Stage **only** the files belonging to the completed task: `git add <file1> <file2>`.
   - **Never run blind `git add .` or `git add -A`** without prior verification.
2. Construct a Conventional Commit message: `<type>(<scope>): <concise description>`.
   - Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`, `build`, `ci`.
3. Verify Git author attribution: check that `user.name` and `user.email` are configured.
4. Execute commit: `git commit -m "<message>"`.
5. Consult: [standards/commit-policy.md](standards/commit-policy.md) & [checklists/pre-commit.md](checklists/pre-commit.md).

### Phase 6: Synchronize with GitHub (When Configured)
1. Check if a remote is configured and auto-push is authorized:
   - Check `.git-workflow.json` (`"auto_push": true`) or explicit operator request.
2. If remote is absent, do not push; inform the operator how to attach a GitHub repository.
3. If remote is present:
   - Run `git fetch <remote> <target-branch>` to check remote state.
   - Check divergence: `git rev-list --left-right --count HEAD...<remote>/<target-branch>`.
   - If behind or diverged, **do not force-push**. Safely rebase or report the conflict.
   - If up-to-date or ahead, execute `git push <remote> <target-branch>`.
   - Verify pushed commit IDs via `git log -1 --stat`.
4. Consult: [standards/github-sync.md](standards/github-sync.md) & [checklists/pre-push.md](checklists/pre-push.md).

---

## 3. Autonomous Operation & Stop-the-World Rules

### What Operates Automatically (No Repeated Prompts)
When a project is configured with `.git-workflow.json` (or standard defaults):
- Routine working tree diff review.
- Incremental documentation updates (`README.md`, `CHANGELOG.md`).
- Test execution and lint validation.
- Selective staging and local Conventional Commits.
- Safe pushing to the authorized GitHub remote (when `auto_push` is true).
- Summarizing completed commits and repository status at the end of each task.

### STOP CONDITIONS: Immediate Operator Authorization Required
Halt automation immediately and request explicit human direction if:
1. **Secrets or Credentials Detected**: Any API token, private key, or password found in diff.
2. **Untracked or Pre-existing Unrelated Changes**: Staging cannot clearly separate current work from prior user edits.
3. **Failing Tests**: Project test suite fails or emits regressions.
4. **Remote History Divergence**: Remote contains commits not in local history (diverged branches).
5. **Destructive Actions**: Request to reset, stash, clean (`git clean -fd`), discard, or amend published commits.
6. **Force-Pushing**: `--force`, `-f`, or `--force-with-lease` is strictly prohibited without explicit user sign-off.
7. **Release Publishing**: Tagging semantic releases or publishing to package registries (PyPI, npm, GitHub Releases).

---

## 4. Documentation Map

| Area | Document | Focus |
| :--- | :--- | :--- |
| **Commit Policy** | [standards/commit-policy.md](standards/commit-policy.md) | Conventional Commits, selective staging, logical chunking, attribution. |
| **GitHub Sync** | [standards/github-sync.md](standards/github-sync.md) | Remote validation, fetch, divergence check, safe push, zero force-pushes. |
| **Doc Standards** | [standards/documentation-policy.md](standards/documentation-policy.md) | README, CHANGELOG, CONTRIBUTING, docs/ hierarchy, sync discipline. |
| **Security** | [standards/security-checks.md](standards/security-checks.md) | Secret scanning, blacklisted files, token regexes, remediation. |
| **Changelog** | [patterns/changelog.md](patterns/changelog.md) | Keep a Changelog 1.1.0 standard, Unreleased section, release cuts. |
| **Project README** | [patterns/project-readme.md](patterns/project-readme.md) | Comprehensive software & CLI README master template. |
| **Project Config** | [patterns/project-config.md](patterns/project-config.md) | `.git-workflow.json` schema, defaults, project isolation rules. |
| **Pre-Commit** | [checklists/pre-commit.md](checklists/pre-commit.md) | 10-point pre-commit verification checklist. |
| **Pre-Push** | [checklists/pre-push.md](checklists/pre-push.md) | 8-point pre-push safety checklist. |
| **Doc Review** | [checklists/documentation-review.md](checklists/documentation-review.md) | 10-point documentation consistency checklist. |

---

## 5. Per-Project Configuration File (`.git-workflow.json`)

To ensure individual projects remain isolated, every repository may contain a `.git-workflow.json` at its root:

```json
{
  "remote_name": "origin",
  "target_branch": "main",
  "auto_commit": true,
  "auto_push": false,
  "test_command": "pytest",
  "docs": {
    "readme": "README.md",
    "changelog": "CHANGELOG.md",
    "contributing": "CONTRIBUTING.md",
    "docs_dir": "docs"
  },
  "secret_scanning": {
    "enabled": true,
    "block_on_detect": true
  },
  "release": {
    "version_file": "pyproject.toml",
    "tag_prefix": "v"
  }
}
```

*When this file is absent, the system uses safe defaults (`remote_name: "origin"`, `target_branch: "main"`, `auto_commit: true`, `auto_push: false`, `secret_scanning.enabled: true`).*
