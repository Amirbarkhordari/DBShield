# Git Workflow & Project Documentation Skill

An automated, disciplined system for change tracking, conventional commits, GitHub synchronization, and project documentation lifecycle across software projects and Linux CLI tools.

---

## Directory Structure

```text
git-workflow-and-project-docs/
├── SKILL.md                          # Antigravity skill definition, 6-phase lifecycle & stopping rules
├── README.md                         # Architecture overview & index
├── standards/                        # Core authoritative standards
│   ├── commit-policy.md              # Staging, Conventional Commits, logical grouping, author attribution
│   ├── github-sync.md                # Remote verification, fetch, divergence check, safe push, zero force-push
│   ├── documentation-policy.md       # README, CHANGELOG, CONTRIBUTING, docs/ hierarchy, sync discipline
│   └── security-checks.md            # Secret detection, blocked files, regex patterns, remediation
├── patterns/                         # Reusable implementation templates & configurations
│   ├── changelog.md                  # Keep a Changelog 1.1.0 standard & release cut patterns
│   ├── project-readme.md             # Production README master template for software & CLI tools
│   └── project-config.md             # .git-workflow.json specification & auto-detection rules
└── checklists/                       # Quality assurance checklists
    ├── pre-commit.md                 # 10-point pre-commit verification checklist
    ├── pre-push.md                   # 8-point pre-push safety checklist
    └── documentation-review.md       # 10-point documentation consistency checklist
```

---

## How to Apply in Future Projects

### 1. Automatic Global Discovery
Installed into your global Antigravity customizations directory:
`~/.gemini/config/skills/git-workflow-and-project-docs/`

The agent automatically discovers and activates this skill across any project when requested to develop features, manage commits, update documentation, or sync with GitHub.

### 2. Per-Project Configuration
Drop a `.git-workflow.json` into any project root to configure target remotes, branches, automated testing, and synchronization settings:

```json
{
  "remote_name": "origin",
  "target_branch": "main",
  "auto_commit": true,
  "auto_push": false,
  "test_command": "pytest"
}
```
