# Documentation Review Checklist

Use this 10-point checklist to audit project documentation for accuracy, consistency, and freshness before finalizing a development task.

---

## 1. Accuracy & Code Synchronization
- [ ] **1. Flags Match `--help`**: Every CLI option in `README.md` and `docs/` matches the exact name, short flag, and default value in the actual code parser.
- [ ] **2. Working Examples**: Invocations in the documentation have been executed and verified. No broken or hypothetical command syntax is documented.
- [ ] **3. Output Samples Updated**: Screen outputs, JSON payload schemas, and tables in docs match current tool outputs.
- [ ] **4. Outdated Syntax Purged**: Deprecated flags, removed subcommands, and obsolete configuration keys have been completely deleted from documentation.

---

## 2. Changelog Integrity
- [ ] **5. Unreleased Section Maintained**: All changes are recorded under `## [Unreleased]` in `CHANGELOG.md`.
- [ ] **6. Correct Category**: Entries are properly filed under `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security`.
- [ ] **7. User-Focused Descriptions**: Notes explain what the change means to the user or developer, not internal variable names.

---

## 3. Structural & Link Quality
- [ ] **8. No Dead Links**: All internal relative file links resolve to real files on disk.
- [ ] **9. No Empty Files**: Every document in `docs/` contains substantial, useful content. No stub or placeholder files exist.
- [ ] **10. Formatting Cleanliness**: Headings follow consistent markdown hierarchy (single `h1`, progressive `h2`/`h3`), with no raw unescaped HTML errors.
