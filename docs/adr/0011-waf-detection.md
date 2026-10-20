# ADR 0011: edge WAF heuristic as a separate field

## Status

Accepted.

## Context

`cdn.Detect` answers who delivers (Cloudflare, Fastly). Users asked what a
WAF detector adds. The exposure question is different: is there a filter in
front? With a WAF, `ips`/`ports` belong to the edge (bypass-to-origin
hypothesis); without a WAF signal, leaked `Server`/`X-Powered-By` is a higher
real exposure. Roadmap already listed WAF/ASN detection.

## Decision

`internal/waf.Detect(cname, header) string` with its own `Result.waf`
(`json:"waf"`, always initialized to `"unknown"`, never null). v1 signals are
presence-only, no `Set-Cookie` read at all:

* Cloudflare: `.cloudflare.net` suffix, `Cf-Ray`, `Cf-Mitigated`, or `Server`
  containing `cloudflare`.
* Sucuri: `.sucuri.net`, `X-Sucuri-Id`, `X-Sucuri-Cache`.
* Incapsula: `.incapsula.com`, `X-Iinfo`.
* DDoS-Guard: `.ddos-guard.net`, `X-Ddos-Guard`.

A match means traffic went through that edge (where WAF can be enabled),
never proof a blocking rule is active. No match means `"unknown"`, never
`"none"`. `Scan` fills WAF on both the success path and the HTTP-fail partial
path (via `Detect(cname, nil)`); human output gains a `waf:` line
(`label.waf` EN+PT).

## Discarded alternatives

* Extend `cdn` instead of a new field: rejected — CDN (who delivers) and WAF
  (who may filter) diverge (Fastly CDN without a WAF signal), one field
  would lie.
* Active probing (send attack payload, check 403): rejected — intrusive,
  out of scope for a passive exposure scanner.
* Parse `Set-Cookie` for `__cf_bm`/`___utmvc`: rejected — values are never
  stored (GO-09); header presence is enough for v1.
* Claim `"none"`: rejected — absence of signal is not proof of absence.

## Consequences

`Result` JSON gains `waf`; `TestResultJSONTags` locks it. Fastly/CloudFront/
Akamai stay `"unknown"` in v1 (declared gap, not a bug). ASN stays on the
roadmap.
