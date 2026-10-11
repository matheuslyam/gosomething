# ADR 0006: Agent workflow on `dev` with green-test loop

## Status

Accepted.

## Context

An LLM implements, the owner reviews via PR. Commits to `main` by the agent
would bypass review; red tests merged would break trust.

## Decision

Agent works on `dev` only, never `main`, in small atomic Conventional Commits
with WHY bodies, pushing `dev`. Before ANY code commit: `gofmt` → `vet` →
`test` → `race` (if available) → `golangci-lint`; red means analyze → fix →
retest until green. Owner opens the PR and merges.

## Consequences

Reviewable history with verified logs. Known env limits are documented in
`AGENTS.md`, never silently used to weaken the gate.
