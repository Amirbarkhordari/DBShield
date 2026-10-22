# Commit Policy Standards

This document establishes the staging discipline, Conventional Commit structure, logical grouping, and author attribution rules for all software projects.

---

## 1. Logical Commits vs Keystroke Commits

Git history is an enduring engineering ledger. It must be clear, bisectable, and informative.

### 1.1 The Golden Rule of Commits
*Every commit must represent a coherent, working, and verifiable unit of change.*

- **Do Not Commit on Every Keystroke**: Avoid micro-commits like `"typo"`, `"wip"`, `"fix 2"`, or `"testing"`.
- **Do Not Batch-Dump Unrelated Work**: Avoid monster commits like `"update scanner and fix database and rewrite readme and bump dependencies"`. Split these into distinct, logical commits:
  1. `feat(scanner): add UDP port discovery`
  2. `fix(db): correct SQLite connection leak on timeout`
  3. `docs: document UDP scanning options in README`
  4. `chore(deps): bump cryptography from 41.0.0 to 42.0.5`
- **Atomic Completeness**: Each commit should compile, pass tests, and leave the repository in a stable state.

---

## 2. Selective Staging Discipline

Never run blind mass-staging commands:
- **FORBIDDEN**: `git add .` or `git add -A` without inspecting `git status` first.
  - Blind staging frequently commits accidental files: `.env`, credentials, OS artifacts (`.DS_Store`, `Thumbs.db`), compiler outputs (`__pycache__`, `target/`, `node_modules`), or unrelated edits made by the operator.
- **MANDATORY**: Explicitly stage only the files relevant to the completed task:
  ```bash
  git add src/cli/scanner.py tests/test_scanner.py README.md CHANGELOG.md
  ```

### 2.1 Staging Checklist
Before staging:
1. Run `git status --short` to see all modified (`M`), added (`?`), or deleted (`D`) files.
2. Run `git diff <file>` to inspect the actual changes.
3. Verify no temporary files or sensitive artifacts are included.
4. Verify documentation changes (`README.md`, `CHANGELOG.md`) are ready to be included in the same commit.

---

## 3. Conventional Commits Specification

All commit messages must adhere to the [Conventional Commits 1.0.0](https://www.conventionalcommits.org/) format:

```text
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### 3.1 Allowed Commit Types
| Type | Purpose | Example |
| :--- | :--- | :--- |
| `feat` | New user-facing feature or CLI command/flag | `feat(cli): add --json output formatting` |
| `fix` | Bug fix in existing logic or behavior | `fix(scanner): prevent timeout crash on unreachable host` |
| `refactor` | Code restructuring without altering functionality | `refactor(core): decouple network adapter from domain logic` |
| `docs` | Documentation updates (README, docs/, docstrings) | `docs(readme): add examples for subnet CIDR scanning` |
| `test` | Adding or correcting unit/integration tests | `test(cli): add test cases for invalid port arguments` |
| `perf` | Code change that improves performance | `perf(parser): optimize regex pattern compilation` |
| `chore` | Routine tasks, build scripts, gitignore, CI workflows | `chore: update .gitignore to exclude test artifacts` |
| `build` | Changes affecting build systems or external dependencies| `build: add packaging configuration in pyproject.toml` |
| `ci` | Changes to CI/CD pipelines (GitHub Actions) | `ci: add automated matrix test workflow` |

### 3.2 Commit Subject Formatting Rules
- **Imperative, present tense**: Use `"add"`, not `"added"` or `"adds"`. Use `"fix"`, not `"fixed"`.
- **Lowercase start**: Do not capitalize the first letter after the colon: `feat: add support...`, not `feat: Add support...`.
- **No trailing period**: Do not end the subject line with a period (`.`).
- **Concise**: Keep the subject line under 72 characters.
- **Accurate**: The description must reflect what the diff actually changes.

### 3.3 Commit Body & Footers
Use the optional body for non-obvious context, architectural rationale, or breaking changes:
```text
feat(scanner): implement raw packet socket probe

Uses AF_PACKET raw sockets to bypass OS TCP stack latency.
Requires CAP_NET_RAW capability or root privileges.

BREAKING CHANGE: --driver flag now defaults to 'raw' instead of 'socket'.
```

---

## 4. Author Identity & Attribution Verification

Before executing a commit, verify that Git author metadata is configured:

```bash
git config user.name
git config user.email
```

### Attribution Rules:
1. If `user.name` or `user.email` is not configured locally or globally:
   - **Do not commit with generic system defaults** (e.g. `root@localhost` or `User <user@desktop>`).
   - Check if GitHub CLI is logged in (`gh auth status`) and configure the matching name/email, or request confirmation from the operator.
2. **Never forge or alter author identity** without explicit instructions.
3. Support `Co-authored-by:` footers when collaborating.

---

## 5. History Integrity

1. **Never Amend Published Commits**: Once a commit has been pushed to a remote shared branch, never run `git commit --amend` or rebase it.
2. **Never Force-Rewrite Shared History**: Do not use `git reset --hard` or `git push --force` on shared branches.
