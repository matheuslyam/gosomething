# ADR 0012: QA harness — from remembered rule to enforced mechanism

## Status

Accepted.

## Context

The qa-gate skill (prose + self-invocation) failed twice on 2026-10-20 in the
same session: P1 committed with no dedicated round, P2 committed before the
verdict table was emitted and with no external QA. Forgetting is the failure
mode, and prose cannot fix forgetting — only an enforced path can. Approved
analogy: an LLM refusal harness works because independent layers back each
other, not because one layer is perfect.

## Decision

Four independent layers (full spec in `docs/qa-gate/05-harness.md`):

1. **Local hook + stamp (ordering enforced).** `scripts/qa-gate.ps1` runs the
   deterministic checks and stamps the exact staged tree hash into
   `.git/qa-stamp`; `pre-commit` rejects anything unstamped; `commit-msg`
   requires a `QA: ...GO...` trailer. `scripts/qa-commit.ps1` is the single
   commit path.
2. **CI backstop (substance server-side).** `.github/workflows/qa.yml`
   (gofmt/vet/test/hygiene, Go 1.27.0 exact) runs on push+PR; red cannot
   merge and stays visible even after a local `--no-verify` bypass.
3. **opencode permissions (agent physically unable).** `git commit *` denied
   (explicit deny survives `--auto`), `git push *` asks (human approves the
   network-irreversible step), only the harness scripts allowed unattended.
4. **Skill as pointer.** `SKILL.md` points at the executable flow instead of
   restating prose; judgment items (acceptance, scope) stay human checklists.

Honest split: scripts/CI verify substance deterministically; the verdict
table keeps judgment items (wording, scope, out-of-scope). The trailer is
audit metadata, not proof.

## Discarded alternatives

* Prose-only skill with stronger wording: rejected — two same-day incidents
  prove wording strength does not change the forgetting failure mode.
* `commit-msg` trailer check alone: rejected — metadata without substance
  checks lets red code through with a honest-looking message.
* Exact-SHA action pins now: rejected — major pins (`checkout@v4`,
  `setup-go@v5`) plus exact `go-version: 1.27.0` are reproducible today;
  SHA pinning is deferred to a future Dependabot pass, not silently dropped.
* `git push` denied like commit: rejected — push to `dev` is the documented
  flow; `ask` keeps a human on the irreversible step without blocking it.

## Consequences

Fresh clones must run `scripts/install-hooks.ps1` (documented in
`CONTRIBUTING.md`; uninstalled hooks fail open locally but CI still guards).
Deliberate bypass (`--no-verify`, forged stamp, hook/config edits) requires
intent and leaves evidence in `git log --grep`, the stamp, and CI — see the
bypass audit in `05-harness.md`. GitHub ruleset (require `qa` check, block
force pushes) is a manual owner step, tracked in `05-harness.md`, never
assumed done.
