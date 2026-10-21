# Architecture

Minimal flow for `exposcan` v1 plus `--secrets` mode (see `docs/adr/`).

```mermaid
flowchart LR
    CLI["cmd/exposcan\nflags + validate"] --> DNS["dns.Resolver\nLookupIPs + CNAME"]
    DNS --> ASN["dns.LookupASN\nCymru origin+asn zones"]
    DNS --> HTTP["httpfetch.Fetcher\nhttps, fallback http"]
    HTTP --> CDN["cdn.Detect\nCNAME + headers"]
    HTTP --> WAF["waf.Detect\nCNAME + headers"]
    HTTP --> PORTS["ports.Check\n80 + 443 parallel"]
    CDN --> OUT["Result | ErrorEnvelope\n human | --json"]
    WAF --> OUT
    ASN --> OUT
    PORTS --> OUT
    CLI --> SEC["secrets.Scan\nHTML+inline+10 JS"]
    SEC --> BODY["httpfetch.BodyFetcher\n2MB cap"]
    BODY --> PAT["patterns\nmasked, --reveal opt-in"]
    PAT --> SECOUT["SecretsResult | ErrorEnvelope\nexit 0/3"]
```

`internal/exposcan.Scan` orchestrates with injected `Deps{DNS, HTTP, Dial}`
under a 15s global context. Partial results carry `HTTPError` warnings;
only DNS failure or context expiry returns an error.

`internal/secrets.Scan` (separate `--secrets` mode) fetches HTML (https with
fallback to http only on transport failure), scans the HTML plus inline
scripts, then up to 10 external `.js` same-origin-first under the same
global context. Single `.js` failures are skipped; HTML failure or context
expiry returns an error. Exit `3` means findings, `0` means clean.
