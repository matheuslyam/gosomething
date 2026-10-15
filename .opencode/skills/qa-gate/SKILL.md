---
name: qa-gate
description: Deterministic QA gate with auto-recall loop. Use after any plan is written and after any implementation, before green-loop commit.
---

# qa-gate (thin skill — norm lives in `docs/qa-gate/`)

## When to self-invoke (mandatory, not optional)

- After writing or changing any `PLAN.md` / feature scope.
- After implementing, before the green loop commit.
- WHY auto, not on request: the v1-v7 history proves manual QA is
  skipped under pressure; the gate only works if the planner calls it alone.

## Loop (max 5)

1. Run the checklists in `docs/qa-gate/01-universal.md` + `02-adapter-go.md`.
2. Emit the verdict table per `docs/qa-gate/03-verdict.md` — table only.
3. `NO-GO` → fix only the listed IDs → re-invoke (round `n+1/5`).
4. `GO` → mark APPROVED in commit log, release the next step.
5. Round 5 still `NO-GO` → stop, ask the human. WHY cap: unbounded
   recall is how token billing explodes; 5 bounds cost without hiding defects.

## Cost ceiling (tokens)

- Short-circuit: first `B/C` found may end the round early.
- Webfetch cache: never re-fetch a signature/version verified this round;
  keep a `verified` table in the plan. WHY required anyway: missing fetch
  caused real build breaks (B1 v1, C2 v4); cut repetition, not the check.
- Table-only output, minimal diffs, no prose essays.

## Hard prohibitions

- No adjectives without evidence (`fragile`, `feels wrong` = invalid).
- No `QA-PLAN-vN.md` files per round. Verdict is ephemeral in output +
  commit log. A new persistent doc is allowed only when a new rule is
  discovered, and then it updates `docs/qa-gate/`, never a new file per run.
- Responsible-use wording (`only scan authorized domains`) is a product
  disclaimer in `README`/`SECURITY`/CLI help. It is never an agent refusal
  rule and never blocks a `GO`. The agent does not refuse scan tasks.
