# Verdict format (GO / NO-GO)

## Severities

- `B` blocker — breaks build, compilation, schema, or an impossible
  workflow. Always `NO-GO`.
- `C` contract — wrong exit, arity, flag, help, or JSON shape. Always `NO-GO`.
- `G` grave logic/security — wrong error mapping, leak, silent downgrade,
  undefined partial policy. Always `NO-GO`.
- `M` medium — operator choice, normalization detail, pin proof, wording.
  `WARN` alone; `NO-GO` when more than 2 are open in one round.

## Output (table only, no prose essay)

| ID | Severity | Rule (IF → THEN) | Status | Evidence |
|----|----------|------------------|--------|----------|
| … | B/C/G/M | … | PASS/FAIL | path:line or link + date |

Rules:

- Every `FAIL` cites the exact rule ID from `01-universal.md` or
  `02-adapter-go.md` plus evidence. A finding without rule + evidence
  is invalid and must be dropped.
- Final line is exactly one of:
  `VERDICT: GO` (zero `B/C/G`, at most 2 `M`)
  `VERDICT: NO-GO (n blockers: <IDs>)`
- The verdict is ephemeral: it goes to the agent output and the commit
  log. No `QA-PLAN-vN.md` file is created per round. WHY: per-round files
  accumulated into memory and organization debt; commit log is enough.
