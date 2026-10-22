# Security Checks and Secret Prevention Standards

This document establishes the automated pre-commit and pre-push security verification standards to prevent credential leaks, private key exposure, and accidental publication of sensitive assets.

---

## 1. Zero Tolerance for Credential Leaks

Once a secret, private key, or access token is committed to Git history, it must be considered **compromised**, even if subsequent commits delete it.

### The Stop-The-World Rule
If any secret, token, private key, or sensitive configuration is detected in staged files or the uncommitted diff:
1. **HALT the commit immediately.**
2. Do not proceed with automatic commit or remote push.
3. Report the detected file and matched pattern to the operator.
4. Provide immediate remediation steps to remove the secret before re-attempting.

---

## 2. High-Risk File Blacklist

The following files must **never** be committed to Git. They must be present in `.gitignore`:

```text
# Environment & Secrets
.env
.env.*
!.env.example
credentials.json
secrets.yaml
config.local.json
token.txt

# Cryptographic Keys & Certificates
id_rsa
id_ecdsa
id_ed25519
*.pem
*.key
*.pkcs12
*.pfx
*.crt

# Temporary & Local Environment
*.tmp
*.bak
*.swp
.DS_Store
Thumbs.db
```

---

## 3. Secret Pattern Signatures

Before staging or committing, scan the diff (`git diff --cached` or `git diff`) against high-confidence secret signatures:

| Secret Category | Regular Expression Pattern |
| :--- | :--- |
| **Private Keys** | `-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----` |
| **GitHub Tokens** | `(ghp\|gho\|ghu\|ghs\|ghr)_[A-Za-z0-9_]{36,255}` |
| **GitHub Fine-Grained**| `github_pat_[A-Za-z0-9_]{82}` |
| **AWS Access Key ID** | `(A3T[A-Z0-9]\|AKIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16}` |
| **AWS Secret Access Key**| `(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]` |
| **Slack Webhook / Token**| `https://hooks.slack.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+` |
| **JWT Tokens** | `eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+` |
| **Generic Passwords** | `(?i)(password\|passwd\|pwd\|api_secret\|client_secret)\s*[:=]\s*['\"][^'\"]{6,}['\"]` |

---

## 4. Automated Diff Scanning Pattern (Python / Bash)

Run this pre-commit check before executing `git commit`:

```bash
# Rapid bash scan on staged diff
git diff --cached --unified=0 | grep -E -i \
  -e "-----BEGIN [A-Z ]*PRIVATE KEY-----" \
  -e "gh[pours]_[A-Za-z0-9_]{36}" \
  -e "github_pat_[A-Za-z0-9_]{82}" \
  -e "AKIA[0-9A-Z]{16}" \
  && {
    echo "[-] SECURITY ALERT: Potential secret detected in staged changes!" >&2
    echo "[-] Commit aborted. Inspect 'git diff --cached' and remove sensitive data." >&2
    exit 1
  }
```

---

## 5. Remediation Procedures

If a secret was accidentally staged or committed locally:

### If Staged (Not Yet Committed):
Unstage the sensitive file immediately:
```bash
git reset HEAD <sensitive-file>
git checkout -- <sensitive-file>
```

### If Committed Locally (Not Pushed):
Reset the commit while keeping other file changes:
```bash
git reset --soft HEAD~1
# Unstage secret and commit cleanly
git reset HEAD <sensitive-file>
```

### If Pushed to Remote (Compromised):
1. **Rotate the secret immediately** in the provider console (GitHub, AWS, etc.). Do not rely on Git history rewrites alone.
2. Expire the old credentials.
3. Clean Git history using `git-filter-repo` or BFG Repo-Cleaner before force-pushing (with operator authorization).
