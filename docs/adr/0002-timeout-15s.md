# ADR 0002: 15s global timeout as boss, inner timeouts as min()

## Status

Accepted.

## Context

Sequential DNS → HTTP → port probes can exceed any single client timeout, and
a `--timeout 5s` flag breaks if inner clients use fixed 10s/5s timeouts.

## Decision

One global `context.WithTimeout` (default 15s, flags 5s/10s/15s/30s) cancels
everything. Inner timeouts are `min(default, global)`: HTTP `min(10s, global)`,
dial `min(5s, global)`.

## Consequences

Invariant: no inner timeout exceeds the global one. Timeout classification
uses `os.IsTimeout` / `Timeout()==true` / `DeadlineExceeded`; `Canceled` is
not a timeout. Discarded: global-only (keep-alive hangs) and inner-only
(no coordinated cancel).
