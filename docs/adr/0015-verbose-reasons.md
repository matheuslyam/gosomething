# ADR 0015: verbose mode with per-signal reasons

## Status

Accepted.

## Context

`cdn: Cloudflare` answers what, never why — triaging the 32 `--secrets`
findings on `cessa.com.br` showed the same need for the exposure scan:
which exact signal fired each heuristic. Roadmap listed verbose mode with
failure reasons.

## Decision

`cdn.Detect`/`waf.Detect` return `(provider, reason)`; reasons name the
exact signal (`cname suffix .cloudflare.net`, `header cf-ray`) or
`no signal`. `Result.Reasons map[string]string` (always initialized, keys
deterministic: `cdn/waf/hsts/csp/server` on every path incl. HTTP-fail)
carries them; `--verbose` prints the `why:` section (fixed key order, never
map iteration). HSTS/CSP reasons distinguish `present/absent (https)` from
`not evaluated (http)` — the https-only rule made visible. `--json` always
includes `reasons` (machines get what humans get with the flag).

## Discarded alternatives

* Re-derive reasons in `main`: rejected — the rule would live twice and
  rot; it lives once, beside the flag it explains.
* Reasons only in human output: rejected — `--json` consumers triage too;
  one source, both renders.
* Verbose as log-level flag affecting all output: rejected — scoped to the
  `why:` section; exit codes, JSON shape, and default human output unchanged.

## Consequences

Detector signatures changed (tests updated with reason asserts, including
a fall-through lock: present-but-unmatched `X-Served-By` must not block
later checks). `TestResultJSONTags` locks `cookies` + `reasons`.
