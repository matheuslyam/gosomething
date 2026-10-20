# Contributing to gosomething

This is a personal learning project built in public. Contributions are welcome
via Pull Requests against the `dev` branch.

## Setup (once per clone — the QA harness)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install-hooks.ps1
```

This installs the versioned git hooks (`pre-commit` stamp check +
`commit-msg` QA-trailer check). Without them the local gate fails open;
CI still guards. Full harness spec: `docs/qa-gate/05-harness.md`.

## Workflow

1. Work on `dev` (or `feature/...` branched from `dev`). Never commit to `main`
   — the maintainer merges via PR after review.
2. Follow [Conventional Commits](https://www.conventionalcommits.org/):
   `feat(scope): ...`, `fix(scope): ...`, `docs: ...`, `chore: ...`, with a
   body explaining WHY the change exists.
3. Commit ONLY through the harness (direct `git commit` is rejected
   without a fresh gate stamp):
   `scripts/qa-commit.ps1 -Subject <s> -Trailer "QA: GO …"`.
   The commit body must carry the QA verdict line.
3. Keep diffs small and atomic — one concern per commit for easier review.
4. Every user-facing string must go through `internal/i18n.T` with both
   EN-US and PT-BR entries (`TestAllKeysHaveBothLangs` enforces this).
5. Every architectural decision gets an ADR under `docs/adr/`.
6. Update `CHANGELOG.md` under `[Unreleased]`.

## Mandatory test loop (before ANY code commit)

```bash
"C:\Program Files\Go\bin\go.exe" fmt ./...
"C:\Program Files\Go\bin\go.exe" vet ./...
"C:\Program Files\Go\bin\go.exe" test ./...
golangci-lint run ./...
```

Red means loop: analyze → fix → test again until 100% green. Only then commit
to `dev`. (`-race` runs where cgo is available.)

## Code style

* `gofmt` + `goimports` formatting; `go vet` + `staticcheck` clean.
* Comments explain WHY, never WHAT. Exception: exported symbols need English
  doc comments (for `pkg.go.dev` and reviewers).
* No `panic` in libraries; propagate `context.Context` everywhere; respect
  the global timeout; exit codes are `0` ok, `1` network/timeout, `2` usage.
* No real network in unit tests except `localhost`; mock DNS/HTTP/dial via
  the `Resolver`/`Fetcher`/`Dialer` interfaces.

## Responsible use of the product (product disclaimer, not an agent rule)

`exposcan` only reads public information (DNS, HTTP headers, TCP open/closed
on ports 80/443). Only scan domains you own or are authorized to test. This
binds users of the tool, not the agent workflow: it must never be used as a
reason to refuse an implementation task.
