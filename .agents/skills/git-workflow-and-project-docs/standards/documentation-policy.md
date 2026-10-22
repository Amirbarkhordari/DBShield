# Documentation Policy Standards

This document establishes the documentation standards, file responsibilities, synchronization workflow, and change log maintenance for all software projects.

---

## 1. Documentation as a First-Class Artifact

Code without accurate documentation is incomplete. Documentation is treated with the same engineering rigor as production code:

1. **Synchronized Commits**: Documentation updates must be included in the **same logical commit** as the code changes, or in a tightly coupled `docs:` commit immediately following.
2. **Zero Outdated Instructions**: When a flag is renamed, an option removed, or a default changed, all documentation referencing the old syntax must be updated simultaneously.
3. **No Speculative Documentation**: Never document features that are incomplete, experimental, or unverified as working capabilities.

---

## 2. Core Documentation Hierarchy

Every project maintains a standardized set of markdown documents:

```text
my-project/
├── README.md               # Primary project overview, quickstart & reference
├── CHANGELOG.md            # Chronological record of user-facing changes
├── CONTRIBUTING.md         # Developer setup, conventions, and PR workflow
└── docs/                   # Deep technical documentation (modular subdocs)
    ├── architecture.md     # Component diagram, data flow, module duties
    ├── cli-reference.md    # Exhaustive flag, argument & subcommand reference
    ├── configuration.md    # Config file schema, env vars & precedence
    └── security.md         # Threat model, privilege boundaries, scope
```

---

## 3. Detailed Document Responsibilities

### 3.1 `README.md` (The Front Door)
Must include:
- **Project Purpose**: 1–2 paragraphs explaining what problem the tool solves.
- **Key Features**: Bulleted highlights of capabilities.
- **System Requirements**: OS support (Ubuntu 22.04/24.04), language runtime, required binaries.
- **Installation**: Step-by-step installation instructions (e.g. `pip install`, `go install`, `cargo install`).
- **Quickstart & Usage**: Copy-pasteable invocations with realistic targets and output examples.
- **Command & Option Reference**: Summary table of flags and subcommands with defaults.
- **Configuration**: How to configure via config files and environment variables.
- **Testing**: How to run the test suite (`pytest`, `go test`).
- **Limitations**: Known trade-offs or platform boundaries.

### 3.2 `CHANGELOG.md` (The Ledger)
Follow [Keep a Changelog 1.1.0](https://keepachangelog.com/) and [Semantic Versioning 2.0.0](https://semver.org/):
- **`[Unreleased]` Header**: Always at the top. Collects ongoing development before release.
- **Standard Subsections**:
  - `### Added` for new features.
  - `### Changed` for changes in existing functionality.
  - `### Deprecated` for soon-to-be-removed features.
  - `### Removed` for now-removed features.
  - `### Fixed` for any bug fixes.
  - `### Security` in case of vulnerabilities addressed.

### 3.3 `CONTRIBUTING.md` (The Contributor Guide)
Document:
- Local development environment setup (virtualenvs, dependencies).
- Code style and linters (`ruff`, `golangci-lint`, `clippy`).
- Testing procedures and test data generation.
- Conventional Commit message rules.
- Pull request submission workflow.

### 3.4 `docs/` Directory (Technical Depth)
Create `docs/` subdocuments **only when needed** by project complexity:
- Never create placeholder or empty files.
- Each document must be focused, comprehensive, and cross-referenced from `README.md`.

---

## 4. Documentation Update Workflow

Follow this 5-step checklist for every completed code change:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   DOCUMENTATION UPDATE WORKFLOW                        │
├─────────────────┬──────────────────────────────────────────────────────┤
│ 1. Identify     │ Which flags, options, behavior, or tests changed?   │
│ 2. Update Docs  │ Modify specific README sections and docs/ subdocs   │
│ 3. Update Log   │ Add bulleted entry under CHANGELOG.md [Unreleased]  │
│ 4. Verify Sync  │ Compare --help output with documentation text        │
│ 5. Stage & Save │ Stage documentation changes together with code diff  │
└─────────────────┴──────────────────────────────────────────────────────┘
```

### 4.1 Incremental Edits vs Blind Overwrites
- **Never regenerate the entire README from scratch** if it already contains tailored project context.
- Update only the affected lines (e.g. updating the flags table, updating command output examples).
- Preserve existing headings, formatting, and project-specific voice.
