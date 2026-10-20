# exposcan (inside `gosomething`)

`gosomething` is a personal Go + networking lab, built in public from day one.
`exposcan` is its first tool: a minimal domain exposure scanner — not an nmap.

Given a domain, it reports the resolved IPs, CNAME, CDN heuristic, WAF heuristic, security
headers and whether ports 80/443 are open. Only scan domains you own or are
authorized to test.

## Quickstart

Requirements: Go 1.27 (`go version go1.27.0`).

```bash
go build -o exposcan ./cmd/exposcan
./exposcan example.com
./exposcan --lang pt exemplo.com
./exposcan --json --timeout 10s example.com
./exposcan --secrets example.com
./exposcan --secrets --reveal example.com
```

## Usage

```text
Usage: exposcan [--lang en|pt] [--timeout 5s|10s|15s|30s] [--json] [--secrets] [--reveal|-rv] <domain>
```

* `--lang en|pt` — output language (default auto: `LANG`/`LC_ALL`, fallback EN).
* `--timeout` — global timeout, one of `5s|10s|15s|30s` (default `15s`).
* `--json` — machine-readable output (`Result` or `SecretsResult`, or `ErrorEnvelope` on failure).
* `--secrets` — hunt leaked frontend secrets (HTML + inline + up to 10 `.js`, same-origin first) instead of the exposure scan.
* `--reveal` (`-rv`) — show full secret values; needs `--secrets`. Default is masked (`AKIA…MPLE`) so logs and videos do not leak secrets.
* Exit codes: `0` scan completed (even partial with warnings, or `--secrets` clean), `1` network
  failure or timeout, `2` usage or validation error, `3` `--secrets` found at least one potential secret.

Example (human):

```text
domain: example.com
punycode: example.com
ips: 93.184.216.34
cname:
cdn: unknown
waf: unknown
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
HTTP headers (`https://`, fallback to `http://` only on transport failure) →
CDN heuristic (CNAME suffix + headers) + WAF heuristic (edge signals, `unknown`
when absent) → TCP probes on 80/443 in parallel.
See `docs/architecture.md` and `docs/adr/`.

Privacy: `Set-Cookie` values are never stored — presence only. `--secrets` is masked by default for the same reason; use `--reveal` only on domains you own, never paste full values into issues or videos.

## Roadmap

* `goreleaser` releases, CI, `revive` lint pass, fuller Diátaxis docs.
* ASN detection, verbose mode with failure reasons, multi-domain input.

## License

MIT — see [LICENSE](LICENSE).
