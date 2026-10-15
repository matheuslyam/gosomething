# Auto-recall loop and live-doc policy

## Flow

```
planner writes/updates scope
  → self-invokes qa-gate (no human prompt needed)
  → NO-GO: fix only listed IDs → re-invoke (round n+1/5)
  → GO: mark APPROVED in commit log → unblock implement
  → post-code: same gate on code → green loop → commit
```

WHY planner + QA stay separate steps even when executed by the same
agent: self-review without the checklist degrades into self-approval.

## Anti-infinite-loop

- Hard cap: 5 rounds per scope. Round 6 does not exist; the agent stops
  and asks the human. WHY: unbounded self-recall is the token-billing
  failure mode.
- Minimal diffs: each fix touches only what the verdict listed.
- Round counter (`round 2/5`) is printed with every verdict for audit.

## Webfetch discipline (required, controlled)

- Required for stdlib signatures (params + returns + conversions) and
  toolchain/dep versions (source + date). Never trust model cutoff.
- Controlled: a `verified` table in the scope caches hits; a second fetch
  of the same fact in the same scope is a loop bug. Short-circuit on the
  first `B/C` is allowed to save tokens.

## Live-doc policy (no accumulation)

- Normative docs live: `docs/qa-gate/01-04.md`, ADRs (only on new
  decisions), `docs/architecture.md` (only on flow change), `CHANGELOG.md`.
- Round verdicts do not live: no file per run, commit log suffices.
- A new persistent QA doc is allowed only when a new rule is discovered,
  and then it amends `01` or `02` — never a new file per finding.
  WHY: `QA-PLAN-vN.md` sprawl was deleted for exactly this reason.
