# Pre-Push Safety Checklist

Use this 8-point checklist before pushing local commits to a remote GitHub repository.

---

## 1. Remote & Branch Verification
- [ ] **1. Remote Verified**: `git remote -v` points to the intended, authorized GitHub repository URL.
- [ ] **2. Correct Target Branch**: Confirmed the target branch is correct (e.g. `main` or designated feature branch).
- [ ] **3. Upstream Configured**: Checked upstream tracking branch (`git rev-parse --abbrev-ref @{u}`).

---

## 2. History & Divergence
- [ ] **4. Fetched & Compared**: Ran `git fetch <remote> <branch>` and checked divergence (`git rev-list --left-right --count HEAD...<remote>/<branch>`).
- [ ] **5. Zero Force-Push**: Standard `git push` is used. `--force`, `-f`, and `--force-with-lease` are strictly avoided.
- [ ] **6. No Divergence Conflict**: Remote does not contain unmerged upstream commits. Local is pure fast-forward ahead.

---

## 3. Publication & Post-Push Verification
- [ ] **7. Secrets Check**: Confirmed that unpushed commits in `@{u}..HEAD` contain zero sensitive credentials or private keys.
- [ ] **8. Push Verified**: Executed `git push` and verified that remote commit hash matches local `HEAD`. Pushed commit ID reported to operator.
