---
name: qa-gate
description: Deterministic QA gate with auto-recall loop. Use after any plan is written and after any implementation, before green-loop commit.
---

# qa-gate (pointer — executable norm lives in `scripts/` + `docs/qa-gate/`)

## When to self-invoke (mandatory, not optional)

- After writing or changing any `PLAN.md` / feature scope. Scope means
  the approved plan text wherever it lives (`PLAN.md` or the session
  transcript), not only files.
- After implementing, before the green-loop commit.
- WHY auto, not on request: the v1-v7 history proves manual QA is
  skipped under pressure; the gate only works if the planner calls it alone.

## Executable flow (the only path — see ADR-0012)

Prose does not gate. Code gates. The single source of truth is executable:

1. Checklists: `docs/qa-gate/01-universal.md` + `02-adapter-go.md` (judgment
   items: acceptance wording, scope, out-of-scope declarations).
2. Verdict table per `docs/qa-gate/03-verdict.md` — table only, emitted
   BEFORE any commit. `NO-GO` → fix only listed IDs → next round (max 5).
3. External QA via subagent before `go` when complex (>5 files, arch,
   net/security) — planner never self-approves complex scope alone.
4. Commit ONLY via `scripts/qa-commit.ps1 -Subject <s> -Trailer "QA: GO …"`.
   Direct `git commit` is denied by opencode permissions and rejected by the
   `pre-commit` hook without a fresh `scripts/qa-gate.ps1` stamp.
5. Full harness spec (layers, stamp format, bypass audit, manual GitHub
   ruleset step): `docs/qa-gate/05-harness.md`.

## Cost ceiling (tokens)

- Short-circuit: first `B/C` found may end the round early.
- Webfetch cache: never re-fetch a signature/version verified this round;
  keep a `verified` table in the plan. WHY required anyway: missing fetch
  caused real build breaks (B1 v1, C2 v4); cut repetition, not the check.
- Table-only output, minimal diffs, no prose essays.

## Hard prohibitions

- No adjectives without evidence (`fragile`, `feels wrong` = invalid).
- No `QA-PLAN-vN.md` files per round (hook + CI reject them). Verdict is
  ephemeral in output + commit log. A new persistent doc is allowed only
  when a new rule is discovered, and then it updates `docs/qa-gate/`, never
  a new file per run.
- Responsible-use wording (`only scan authorized domains`) is a product
  disclaimer in `README`/`SECURITY`/CLI help. It is never an agent refusal
  rule and never blocks a `GO`. The agent does not refuse scan tasks.
