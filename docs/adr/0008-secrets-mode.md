# ADR 0008: --secrets mode (separate, masked by default, exit 3)

## Status

Accepted.

## Context

Bancada goal: `exposcan --secrets <domain>` hunts leaked frontend secrets in
HTML and JavaScript as a real Go+HTTP study, with conditional video only on
findings. Constraints: 1-2 nights PROD, global timeout is boss, bilingual
CLI, stable JSON, no real network in tests except localhost.

## Decision

1. Separate mode: `--secrets` runs only the secrets hunt, never the exposure
   scan together. WHY: distinct output, distinct exit code, smaller scope.
2. Scope: scan the HTML itself + inline `<script>` + up to 10 external
   `<script src>` in document order, same-origin first, third parties
   included. WHY: user decision 2026-10-15 for maximum bancada coverage;
   same-origin-first keeps the authorized domain priority when truncating.
3. Caps: 2MB per file (prefix still scanned, `truncated:true`), global
   `context` boss with inner `min(10s, global)` body timeout. WHY: prevents
   OOM and keeps 10 sequential fetches inside 15s for normal bundles.
4. Masked by default with opt-in `--reveal` (alias `-rv`, same bool var).
   WHY: terminal/shell/CI/video logs leak full secrets; mask shows
   `first4…last4` for triage. `--reveal` without `--secrets` is exit 2.
5. Exit 3 with findings (0 clean, 1 total network/timeout, 2 usage).
   WHY: scripts need a distinct "completed with findings" code for
   conditional video. `1`/`2` keep precedence on total failure.
6. Separate JSON envelope `SecretsResult{domain,punycode,filesScanned,
   findings,truncated}`; `Finding{file,line,pattern,masked,value?}` with
   `value` only on `--reveal`. WHY: `Result` of the normal scan stays stable.

## Consequences

`x/net/html` (already required) parses scripts — no new dependency. Single
`.js` failures are skipped, never fatal; HTML failure is fatal (exit 1).
Tests use `httptest` localhost fixtures with fake keys only.

Discarded: coupled scan+secrets (WHY: doubles time/network by default);
same-origin-strict only (WHY: misses third-party leaks, but safer scope);
always-full-value (WHY: leak amplifier, same reason as Set-Cookie presence
only); extending `Result` (WHY: breaks existing consumers).
