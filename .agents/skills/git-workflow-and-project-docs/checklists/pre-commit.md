# Pre-Commit Verification Checklist

Use this 10-point checklist before creating any local Git commit.

---

## 1. Staging & Diff Hygiene
- [ ] **1. Selective Staging**: Only files directly modified for the current task are staged. No blind `git add .` was used.
- [ ] **2. No Unintended Edits**: Checked `git diff --cached` to verify no accidental whitespace, formatting churn, or unrelated user edits are included.
- [ ] **3. No Build Debris**: No temporary files, `.tmp`, cache directories (`__pycache__`, `node_modules`, `target`), or OS files (`.DS_Store`) are staged.

---

## 2. Security & Credentials
- [ ] **4. Zero Secrets**: Staged diff scanned for API keys, private keys, JWTs, AWS credentials, and passwords. All tests passed clean.
- [ ] **5. Environment Files Excluded**: `.env`, `.env.local`, and credential files are present in `.gitignore` and not tracked.

---

## 3. Quality & Tests
- [ ] **6. Tests Passed**: Project test suite was executed (`test_command`) and completed with 100% passing tests.
- [ ] **7. Linters & Syntax**: Code passes static analysis, type checks, or linter rules without errors.

---

## 4. Documentation & History
- [ ] **8. Documentation Synced**: Any changes to flags, options, config, or behavior are accurately reflected in `README.md` and `docs/`.
- [ ] **9. Changelog Updated**: A clear, bulleted summary of changes is recorded under `## [Unreleased]` in `CHANGELOG.md`.
- [ ] **10. Conventional Message**: Commit message adheres to Conventional Commits: `<type>(<scope>): <actionable summary>`.
