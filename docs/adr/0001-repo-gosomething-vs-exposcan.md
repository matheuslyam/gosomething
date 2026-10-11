# ADR 0001: Repo `gosomething` with tool `exposcan`, rename left open

## Status

Accepted.

## Context

The lab may stay a single tool (`exposcan`) or grow into a mix of cybersec
tools. Renaming the repo now would churn remote, module path and docs.

## Decision

Keep repo `gosomething` as the lab; first tool lives at `cmd/exposcan`.
Revisit the rename only when a second tool lands or the owner decides.

## Consequences

Module path stays `github.com/matheuslyam/gosomething`. No rename cost now;
a future rename needs module + import migration (recorded here when decided).
