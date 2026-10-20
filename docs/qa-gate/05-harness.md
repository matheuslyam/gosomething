# Harness: enforced QA path (normative, implements ADR-0012)

Prose remembers. Code enforces. This file is the executable-adjacent norm:
every behavior below is implemented in `scripts/` + `.github/` +
`opencode.json`, not wished for.

## Layers

| # | Layer | Enforces | Lives in |
|---|-------|----------|----------|
| 1 | Stamp + hooks | verdict-before-commit ordering | `scripts/qa-gate.ps1`, `scripts/qa-commit.ps1`, `scripts/hooks/`, `scripts/install-hooks.ps1` |
| 2 | CI | red cannot merge, stays visible | `.github/workflows/qa.yml` |
| 3 | Permissions | agent cannot commit directly | `opencode.json` → `permission.bash` |
| 4 | Pointer skill | single source of truth is code | `.opencode/skills/qa-gate/SKILL.md` |

## Stamp format (`.git/qa-stamp`, untracked, written only by the gate)

```text
tree=<git write-tree hash of the staged index>
verdict=GO
at=<UTC ISO-8601>
by=scripts/qa-gate.ps1
```

`pre-commit` recomputes `git write-tree` and requires an exact `tree=` line
match. WHY staged-tree hash, not "gate ran at time T": the gate may have run
on different bytes; only identical staged bytes are stamped. Any edit after
the gate → mismatch → reject → re-run the gate.

## Hook behaviors (exact)

* No stamp file → reject: `BLOCKED: no .git/qa-stamp…`
* Stamp tree ≠ staged tree → reject: `BLOCKED: staged tree … has no GO stamp…`
* Staged `QA-PLAN-*.md` → reject (verdicts live in output + commit log).
* Commit message without `/QA:.*GO/` (case-insensitive) → reject.
* Trailer regex is audit metadata, not proof; proof is gate green + CI green.

## opencode permissions (exact)

```json
"bash": {
  "*": "ask",
  "git commit *": "deny",
  "git push *": "ask",
  "*qa-gate.ps1*": "allow",
  "*qa-commit.ps1*": "allow",
  "*install-hooks.ps1*": "allow"
}
```

WHY last-match-wins ordering: `git commit` matches `*` then `git commit *`
→ deny holds even under `--auto` (explicit deny is enforced). WHY push is
`ask` not `deny`: push to `dev` is the documented flow; the human approves
the network-irreversible step.

## CI (exact)

`.github/workflows/qa.yml`, on push+PR, `ubuntu-latest`, `setup-go`
`go-version: 1.27.0` exact: `gofmt -l` empty, `vet` clean, `test` green,
no `QA-PLAN-*.md`. WHY ubuntu: suite is portable (localhost + dynamic
ports), which also proves the code is not Windows-coupled.

## Setup (fresh clone)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install-hooks.ps1
```

Without installed hooks layer 1 fails open locally; layer 2 (CI) still
guards. Never assume hooks are installed — verify with a real rejected
commit, not by reading the directory.

## Manual owner step (NOT automated — tracked here, never assumed)

GitHub ruleset on `dev` + `main` (Settings → Rules → Rulesets → New):

* Require status checks to pass: `qa` (blocks merge on red).
* Block force pushes.
* Status on 2026-10-20: pending (no owner action taken yet).

## Bypass audit (deliberate bypass requires intent + leaves evidence)

| Bypass | Evidence left |
|--------|---------------|
| `git commit --no-verify` | commit without/with stale stamp; CI still runs red/green on substance; `git log` shows missing QA discipline |
| Forged `.git/qa-stamp` | stamp `at`/`by` vs actual tree; CI re-verifies substance independently |
| Edited/deleted hooks | `scripts/hooks/` sources versioned — `git status`/`git diff` shows it; fresh-clone install restores |
| Edited `opencode.json` permissions | change is in the diff itself, reviewable |
| Trailer without green gate | `commit-msg` accepts metadata; CI checks substance; table missing from session output |

Accidental skipping (100% of incidents to date: forgotten table, missing
external QA, unrounded scope) is eliminated: there is no path from red or
unstamped content to a commit that does not actively fight the harness.
