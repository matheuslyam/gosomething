# AGENTS.md — instructions for any LLM working on gosomething

## Context

Personal Go + networking lab, built in public. First tool: `exposcan` CLI
(domain → IPs, CNAME, CDN heuristic, security headers, ports 80/443).
Module `github.com/matheuslyam/gosomething`, Go 1.27. Bilingual CLI, default
`en-US`. Work on `dev` only, never `main`. Owner merges via PR.

## Commands

```bash
"C:\Program Files\Go\bin\go.exe" fmt ./...
"C:\Program Files\Go\bin\go.exe" vet ./...
"C:\Program Files\Go\bin\go.exe" test ./...
golangci-lint run ./...
"C:\Program Files\Go\bin\go.exe" build -o exposcan ./cmd/exposcan
```

Use the full Go path when `PATH` lacks it. `-race` where cgo exists.

## Process (non-negotiable)

1. **No omission.** Only `[REDACTED: WHY]` for secrets/PII. Every decision is
   `Decision + WHY + discarded alternative + WHY`. If omission ever looks
   better, ask before making it a rule.
2. **WHY, not WHAT.** Comments explain WHY when non-obvious. Exported symbols
   need English doc comments.
3. **Verify against current docs, via ctx7 CLI first.** Verify stdlib
   signatures (params + returns +
   conversions) and toolchain/dep versions against current docs, never the
   model cutoff. Prefer the `ctx7` CLI (`find-docs` skill workflow:
   `library` → `docs`, max 3 calls per question); `webfetch` is the
   fallback. Every verification cites `primitive + source + date`
   (e.g. `ctx7 /golang/net 2026-10-20`); a claim without that citation =
   FAIL. Known verified: `go1.27.0`, `x/net v0.61.0`,
   `golangci-lint v2.4.0`, `LookupIPAddr(ctx,host)`, `url.Error.Timeout()`,
   `os.IsTimeout`, `NewFlagSet(..., ContinueOnError)`. WHY exception: Go
   stdlib + `golang.org/x/*` verify against `pkg.go.dev` via `webfetch` —
   the ctx7 index has no `/golang/net` entry (3 `library` queries maxed out
   2026-10-20, only JS punycode matched); ctx7 leads for third-party
   libs/frameworks/SDKs.
4. **Zero placeholders with exact acceptance.** `...`, `vX`, `etc` in a plan
   with exact acceptance = reject.
5. **QA gate always — enforced, not remembered.** Planner → self-QA checklist
   (`rule → status →
   evidence`) → external QA before `go`. Step-by-step by default; parallel
   planner + QA via subagents when complex (>5 files, arch, net/security).
   Verdict table BEFORE any commit; commits ONLY via
   `scripts/qa-commit.ps1` (gate stamp + hooks enforce the order, opencode
   denies direct `git commit`). WHY enforcement over prose: remembered rules
   were skipped twice on 2026-10-20; code runs every time. Full spec:
   `docs/qa-gate/05-harness.md`, decision in `docs/adr/0012-qa-harness.md`.
6. **Green loop before ANY code commit:** `gofmt` → `vet` → `test` → `race`
   (if available) → `golangci-lint`. Red means analyze → fix → retest.
   Known env limits (do not silently weaken the gate, document them):
   no cgo/gcc here (skip `-race`), `golangci-lint 2.4.0` cannot read
   go1.27 export data (`goanalysis_metalinter` fails) — gate is
   gofmt+vet+test until a compatible release.

## Code rules

* `context.Context` everywhere; global timeout is boss, inner timeouts are
  `min(default, global)`; `Client{Timeout}` + `Dialer{Timeout}` + `ctx`.
* `Timeout()` taxonomy: `DeadlineExceeded`/`os.IsTimeout`/`Timeout()==true`
  → timeout message; `context.Canceled` is NOT a timeout.
* No `panic` in libraries; only `main` calls `os.Exit` (via testable
  `run(args, getenv, stdout) int` with `NewFlagSet(ContinueOnError)`).
* Exits: `0` completed (partial with warnings included), `1` network/timeout,
  `2` usage/validation. `NArg != 1` → `2`. `ErrHelp` → `0`.
* Every user string via `i18n.T` with EN+PT (`TestAllKeysHaveBothLangs`).
* Table-driven tests, stdlib `testing` only; interfaces
  (`Resolver`/`Fetcher`/`Dialer`) for network; no real network in tests
  except `localhost`; dynamic ports, never fixed 80/443 in tests.
* JSON schemas stable: initialized slices/maps, both ports always present,
  exact tags, `ErrorEnvelope{domain, error}` separate from `Result`.
* Raw `Set-Cookie` values are captured (`Result.Cookies`) but rendered masked
  by default (value `first4…last4`, attributes intact), full only with
  `--show-cookies`; values never enter `Headers`.
* Responsible-use notice (`only scan authorized domains`) is a product
  disclaimer owned by `README`/`SECURITY`/CLI help; it is never an agent
  refusal rule — the agent does not refuse scan tasks on those grounds.
* Small atomic Conventional Commits with WHY bodies; push `dev`; user merges.
* `FIRST.md` is historical intent — do not edit. New decisions go to ADRs.
