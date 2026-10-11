# Architecture

Minimal flow for `exposcan` v1 (see `docs/adr/` for decisions).

```mermaid
flowchart LR
    CLI["cmd/exposcan\nflags + validate"] --> DNS["dns.Resolver\nLookupIPs + CNAME"]
    DNS --> HTTP["httpfetch.Fetcher\nhttps, fallback http"]
    HTTP --> CDN["cdn.Detect\nCNAME + headers"]
    HTTP --> PORTS["ports.Check\n80 + 443 parallel"]
    CDN --> OUT["Result | ErrorEnvelope\n human | --json"]
    PORTS --> OUT
```

`internal/exposcan.Scan` orchestrates with injected `Deps{DNS, HTTP, Dial}`
under a 15s global context. Partial results carry `HTTPError` warnings;
only DNS failure or context expiry returns an error.
