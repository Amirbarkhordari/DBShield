# Changelog Patterns

This document provides reusable templates and maintenance patterns for `CHANGELOG.md` following [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

---

## 1. Master Changelog Template

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Feature description with relevant flag or capability details.

### Changed
- Details of modified behavior or updated defaults.

### Deprecated
- Features slated for removal in future versions.

### Removed
- Features or flags removed in this release.

### Fixed
- Bug fixes and resolved edge cases.

### Security
- Vulnerability patches and credential handling improvements.

## [1.0.0] - 2026-10-22

### Added
- Initial release of the application.
- Command-line interface with `--help` and `--version`.
```

---

## 2. Unreleased Section Maintenance Workflow

During ongoing development, all meaningful changes are appended under `## [Unreleased]`:

### Rules for Entries:
1. **Categorized**: Always place changes under one of the 6 standard subsections: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
2. **User-Centric**: Write from the perspective of the developer or operator using the tool, not internal variable names.
   - **Good**: `- Added '--timeout' option to configure connection deadlines [default: 30s].`
   - **Bad**: `- changed self.t_limit to 30 in client.py.`
3. **Commit Association**: Include the pull request or commit reference when known: `([#42](https://github.com/owner/repo/pull/42))`.

---

## 3. Cutting a Release Pattern

When cutting a semantic release (e.g. `v1.1.0`):
1. Rename `## [Unreleased]` to `## [1.1.0] - YYYY-MM-DD`.
2. Insert a fresh empty `## [Unreleased]` block at the very top.
3. Update version metadata in project configuration (`pyproject.toml`, `package.json`, `Cargo.toml`, etc.).
4. Commit the release change:
   ```bash
   git commit -am "chore(release): cut v1.1.0"
   git tag -a v1.1.0 -m "Release v1.1.0"
   ```
