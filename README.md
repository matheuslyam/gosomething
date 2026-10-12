# exposcan (inside `gosomething`)

`gosomething` is a personal Go + networking lab, built in public from day one.
`exposcan` is its first tool: a minimal domain exposure scanner — not an nmap.

Given a domain, it reports the resolved IPs, CNAME, CDN heuristic, security
headers and whether ports 80/443 are open. Only scan domains you own or are
authorized to test.

## Quickstart

Requirements: Go 1.27 (`go version go1.27.0`).

```bash
go build -o exposcan ./cmd/exposcan
./exposcan example.com
./exposcan --lang pt exemplo.com
./exposcan --json --timeout 10s example.com
```

## Usage

```text
Usage: exposcan [--lang en|pt] [--timeout 5s|10s|15s|30s] [--json] <domain>
```

* `--lang en|pt` — output language (default auto: `LANG`/`LC_ALL`, fallback EN).
* `--timeout` — global timeout, one of `5s|10s|15s|30s` (default `15s`).
* `--json` — machine-readable output (`Result`, or `ErrorEnvelope` on failure).
* Exit codes: `0` scan completed (even partial with warnings), `1` network
  failure or timeout, `2` usage or validation error.

Example (human):

```text
domain: example.com
punycode: example.com
ips: 93.184.216.34
cname:
cdn: unknown
ports: 80=open 443=open
hsts: true
csp: false
server: true
headers:
  server: nginx
```

## How it works

`validate` (IDN via `idna.Lookup`, no network) → DNS (`LookupIPAddr`+CNAME) →
HTTP headers (`https://`, fallback to `http://` only on transport failure) →
CDN heuristic (CNAME suffix + headers) → TCP probes on 80/443 in parallel.
See `docs/architecture.md` and `docs/adr/`.

Privacy: `Set-Cookie` values are never stored — presence only.

## Roadmap

* `goreleaser` releases, CI, `revive` lint pass, fuller Diátaxis docs.
* WAF/ASN detection, verbose mode with failure reasons, multi-domain input.

## License

MIT — see [LICENSE](LICENSE).
