# GitHub Synchronization Standards

This document establishes the protocols for connecting GitHub repositories, verifying remotes, synchronizing commits, handling divergence, and enforcing non-destructive push policies.

---

## 1. Remote Verification & Authentication Discipline

Before initiating any remote Git operation:

### 1.1 Remote Configuration Checks
1. Check existing remotes:
   ```bash
   git remote -v
   ```
2. Verify remote URL:
   - Does it point to the expected repository (e.g. `https://github.com/owner/repo.git` or `git@github.com:owner/repo.git`)?
   - Is it using HTTPS with Git Credential Manager or SSH with configured keys?
3. If no remote exists and the operator provides a repository URL:
   - Verify repository existence and access using GitHub CLI:
     ```bash
     gh repo view <owner/repo>
     ```
   - Add the remote:
     ```bash
     git remote add origin <URL>
     ```

### 1.2 Authentication Rule
- **NEVER ASK FOR SECRETS IN CHAT**: Never ask the operator to paste GitHub personal access tokens (PAT), passwords, or private SSH keys into chat or documentation.
- **Rely on Ambient Credentials**:
  - Use GitHub CLI credential helper (`gh auth git-credential`).
  - Use Git Credential Manager (GCM).
  - Use local SSH agent (`ssh-agent`).
- If authentication fails, report the failure with clear remediation (e.g. `"Run 'gh auth login' in your terminal"`).

---

## 2. Remote Synchronization Lifecycle

Follow this 5-step synchronization lifecycle:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   GITHUB SYNCHRONIZATION CYCLE                         │
├─────────────────┬──────────────────────────────────────────────────────┤
│ 1. Fetch        │ git fetch <remote> <branch>                          │
│ 2. Inspect      │ Compare local HEAD with remote tracking branch       │
│ 3. Check Status │ Ahead / Behind / Diverged                            │
│ 4. Push (Safe)  │ git push <remote> <branch> (if ahead and up-to-date) │
│ 5. Verify       │ Confirm remote commit ID matches local HEAD          │
└─────────────────┴──────────────────────────────────────────────────────┘
```

### Step 1: Fetch Remote
Fetch changes quietly without modifying the local working tree:
```bash
git fetch origin main
```

### Step 2: Check Divergence
Compare local `HEAD` and `origin/main`:
```bash
# Returns two numbers: [ahead, behind]
git rev-list --left-right --count HEAD...origin/main
```

### Step 3: Divergence Matrix and Resolution
| State | Ahead | Behind | Action |
| :--- | :--- | :--- | :--- |
| **Up to Date** | `0` | `0` | Nothing to push. Clean state. |
| **Pure Ahead** | `> 0` | `0` | Safe to push immediately. Local is strictly ahead of remote. |
| **Pure Behind** | `0` | `> 0` | Local is behind. Fast-forward pull: `git pull --ff-only origin main`. |
| **Diverged** | `> 0` | `> 0` | **HALT!** Remote contains commits not in local branch. |

---

## 3. Strict Divergence & Non-Destructive Push Policy

### 3.1 Force-Push Prohibition
- **NEVER force-push** (`git push --force`, `git push -f`, or `git push --force-with-lease`) on shared or default branches (`main`, `master`, `release/*`).
- Force-pushing overwrites history, destroys peer commits, and invalidates collaborator checkouts.

### 3.2 Handling Divergence Safely
If branches have diverged:
1. **Do not force-push.**
2. Attempt a safe rebase if local commits are unpushed work:
   ```bash
   git pull --rebase origin main
   ```
3. If conflicts occur:
   - **Stop immediately!**
   - Do not guess or silently discard conflicted code.
   - List conflicted files and prompt the operator to review conflict markers (`<<<<<<< HEAD`).

---

## 4. Verification and Reporting

Never claim that a commit was pushed without verifying the result:

1. **Verify Push Success**:
   ```bash
   git rev-parse HEAD
   git rev-parse origin/main
   # Both hashes must match!
   ```
2. **Report to Operator**:
   State clearly:
   - The remote repository name and branch (`origin/main`).
   - The exact commit hashes and commit messages pushed.
   - The URL to view the commits on GitHub (if known).

### 4.1 Offline or Disconnected Operations
If network access is unavailable, GitHub credentials are missing, or `auto_push` is disabled:
- Proceed with safe local development and local commits.
- Clearly inform the operator:
  ```text
  [+] Changes committed locally (commit: a1b2c3d).
  [*] Remote push skipped (GitHub synchronization not configured/authorized).
  ```
