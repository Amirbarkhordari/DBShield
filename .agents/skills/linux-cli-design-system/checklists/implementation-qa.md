# Implementation QA Checklist

Use this checklist and test matrix to verify functional behavior, exit code contracts, and pipeline compatibility before certifying a CLI tool.

---

## 1. Functional CLI Test Matrix

Execute each test case against the actual compiled or scripted CLI binary:

| ID | Test Scenario | Command Pattern | Expected Result | Pass? |
| :--- | :--- | :--- | :--- | :--- |
| **T01** | Root Help | `tool --help` | Exit `0`, prints usage and options | [ ] |
| **T02** | Subcommand Help | `tool <subcommand> --help` | Exit `0`, prints command-specific options | [ ] |
| **T03** | Version Output | `tool --version` | Exit `0`, prints version string | [ ] |
| **T04** | Missing Required Arg | `tool <subcommand>` (no args) | Exit `2`, prints clear error & remedy | [ ] |
| **T05** | Invalid Flag | `tool --nonexistent-flag` | Exit `2`, rejects flag, suggests `--help` | [ ] |
| **T06** | Invalid Value | `tool scan --ports 99999` | Exit `2`, reports out-of-range value | [ ] |
| **T07** | Successful Run | `tool scan --target 127.0.0.1` | Exit `0`, renders clean output & summary | [ ] |
| **T08** | Operational Failure | `tool scan --target 192.0.2.1` | Exit `1` or `4`, prints 3-part error | [ ] |
| **T09** | JSON Output Validity | `tool scan --target 127.0.0.1 --json \| jq .` | Exit `0`, `jq` validates without error | [ ] |
| **T10** | Stdin Redirection | `cat targets.txt \| tool scan` | Exit `0`, reads targets from stdin | [ ] |
| **T11** | Non-TTY / Batch | `tool scan --target 127.0.0.1 < /dev/null` | Does not hang; exits cleanly | [ ] |
| **T12** | User Interrupt (Ctrl+C)| `tool scan` then press `Ctrl+C` | Exit `130`, cleans up temp files | [ ] |
| **T13** | NO_COLOR Test | `NO_COLOR=1 tool scan --target 127.0.0.1` | Output contains zero `\033` escape codes | [ ] |
| **T14** | Broken Pipe Handling | `tool list \| head -n 1` | Exits cleanly without `BrokenPipeError` | [ ] |

---

## 2. Stream Separation Verification

Run this test to ensure diagnostics do not leak into data streams:

```bash
# 1. Run command with split streams
tool scan --target 127.0.0.1 --format json 1> /tmp/payload.json 2> /tmp/diagnostics.log

# 2. Check that payload is valid JSON and contains no banners
jq -e . /tmp/payload.json > /dev/null && echo "[+] Payload is pure JSON"

# 3. Check that progress and status lines went to diagnostics
grep -q -E "\[\*\]|\[\+\]" /tmp/diagnostics.log && echo "[+] Diagnostics captured in stderr"
```

---

## 3. Real Functionality Rule

- [ ] **No Hardcoded Data**: Verify that results, scan statistics, and table rows are dynamically generated from real operations, never hardcoded strings designed to simulate completion.
- [ ] **No Hidden Failures**: Verify that API or system errors do not get swallowed silently while returning exit code `0`.
