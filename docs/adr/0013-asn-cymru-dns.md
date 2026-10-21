# ADR 0013: ASN enrichment via Team Cymru DNS

## Status

Accepted.

## Context

`Result` maps where traffic goes (IPs, CDN/WAF edge) but not who announces
the route. The `cessa.com.br` analysis showed the gap: knowing the IP is
Cloudflare's edge invites the bypass question, which starts from the origin
AS (who owns the netblock, which RIR, since when). Roadmap listed ASN
detection as the natural next step.

## Decision

`dns.LookupASN(ctx, ip) ([]ASNRecord, error)` on the existing `Resolver`
interface, backed by Team Cymru DNS (verified 2026-10-20/21 in
`team-cymru.com/ip-asn-mapping`): reversed-octets/nibbles TXT query on the
`origin`/`origin6` zones (`"ASN | prefix | CC | registry | allocated"`,
no name there), then one `AS<asn>.asn.cymru.com` query per distinct ASN for
the org name. `Result.ASNs []dns.ASNRecord` (always initialized, per-IP
order = `IPs` order), failures tolerated to `Org "unknown"` (enrichment is
best-effort, like CNAME). Human prints `ip -> AS<n> (org, prefix, reg
CC/registry)`; `reg` marks registry provenance, never geolocation.

## Discarded alternatives

* HTTP API (bgpview/ipinfo): rejected — external dependency + rate limits
  for data DNS already gives, free and cacheable.
* MaxMind `.mmdb`: rejected — binary in repo + license + manual updates.
* New `ASNResolver` interface: rejected — one DNS collaborator, one mock;
  two interfaces would double stub surface in every scan test.
* Single `asn` field: rejected — multihoming (Cymru FAQ) makes one ASN a
  lie; per-IP list stays honest.
* CC as location: rejected — anycast (the `-GRU` cf-ray vs ARIN/US record
  on the same IP) proves registry CC is not server location.

## Consequences

`Result` JSON gains `asns`; `TestResultJSONTags` locks it. Name lookup is
sequential per IP (usually one ASN), per-IP lookups run parallel in `Scan`.
Cymru NXDOMAIN (bogons, unallocated) → `unknown`, never an error.
