# ADR 0014: raw Set-Cookie capture with masked-by-default rendering

## Status

Accepted. Amends the Set-Cookie half of GO-09 (never-stored becomes
captured-raw, masked-by-default, full-only-with-flag).

## Context

GO-09 stored presence only. The `cessa.com.br` analysis proved the gap:
without flags (`Secure`, `HttpOnly`, `SameSite`, `__Host-`) and without the
value shape, session exposure cannot be mapped — and presence alone answers
nothing. The user chose full raw capture over names+flags.

## Decision

`Result.Cookies []string` holds raw `Set-Cookie` values (collection in
`Scan`, redaction at render). Human and `--json` output mask the value
(`name=first4…last4`, attributes intact — attributes are the audit signal,
the value is the secret), full values only under `--show-cookies`. Masking
mirrors `secrets.Mask` (`<8` chars → `****`). `Headers` allowlist unchanged:
cookie values never enter `Headers` (the existing allowlist test still
guards that).

## Discarded alternatives

* Names + flags only, never values: rejected — user decision; raw preserves
  attributes a parser might drop and allows exact replay.
* Reuse `--reveal`: rejected — `--reveal` is locked to `--secrets` mode
  (`err.badReveal`); the normal scan must not inherit secrets-mode flag
  semantics. A dedicated `--show-cookies` keeps the modes orthogonal.
* Mask at collection (store masked): rejected — the raw value would be
  unrecoverable even with the flag; collect raw, redact at the edge.

## Consequences

`Result` JSON gains `cookies` (masked by default, raw with the flag —
`--json` without the flag must never exfiltrate sessions to disk).
`TestResultJSONTags` locks both keys. Fixtures use fake values (GO-16).
README privacy lines, AGENTS.md, and GO-09 rewritten in this batch.
