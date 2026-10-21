# Adapter: Go + `exposcan` (instantiation of the universal core)

Use together with `01-universal.md`. Each item maps to a universal ID.

## Signatures and compilation (`AC-01`, `SC-01`)

- `GO-01` Every function/type is pasted complete with conversions
  (`LookupIPAddr(ctx,host)` + `a.IP` loop, `url.Error.Timeout()`,
  `os.IsTimeout`, `NewFlagSet(..., ContinueOnError)`). `Deps` fields typed.
  WHY: omitted conversions broke compilation in v1/v3. Every verification
  cites `primitive + source + date` (`ctx7` CLI preferred, `webfetch`
  fallback); a signature/version claim without that citation is FAIL.
  WHY citation: unverified-from-memory signatures caused real build breaks;
  the primitive (not just the URL) tells the next reader what to re-run.

## CLI contract (`AC-01`, `SC-02`, `DF-01=C`)

- `GO-02` `run(args,getenv,stdout) int`, `NewFlagSet(ContinueOnError)` +
  `SetOutput(stdout)` + custom `Usage`. `ErrHelp → 0`, parse error → 2,
  `NArg != 1 → 2` with `Domain = Arg(0)` or `""`. Exits `0/1/2` mapped,
  plus secrets-mode `3` (≥1 finding, never a failure) and `0` clean.
- `GO-03` `peekLang` handles `--lang pt`, `--lang=pt`, absent, invalid;
  it decides message language only, never flag order validity.

## Validation order (`SC-02`)

- `GO-04` `TrimSpace → strip one trailing dot → empty? → contains "."?`
  (else `singleLabel` before `idna`) → `idna.Lookup.ToASCII` (errors →
  `badChars`) → `253/63` limits → charset/edges/`..`. `ErrOK` defined,
  `original` normalized without trailing dot, case preserved.
  WHY: order decides the error message; wrong order lies to the user.

## Network and timeout (`SC-02`, `EN-01`)

- `GO-05` Global timeout is boss; inner are `min(default, global)`:
  HTTP `min(10s, global)`, dial `min(5s, global)`; `Client{Timeout}` +
  `Dialer{Timeout}` + `ctx` everywhere.
- `GO-06` `isTimeout = DeadlineExceeded / os.IsTimeout / Timeout()==true`;
  `context.Canceled` is NOT a timeout (maps to generic fail, exit still 1).
- `GO-07` `shouldFallbackToHTTP` is an exact predicate
  (timeout / `ECONNREFUSED` / TLS verification errors), never status codes.
  Redirects ≤ 3, `LimitReader 1MB`, body `Close()`, `FinalURL` defined.
  WHY: silent `https → http` downgrade hides a security signal.

## Partial vs fatal (`SC-01`, `DF-01=G`)

- `GO-08` `LookupIPs` error is fatal (`ErrorEnvelope`, exit 1);
  `CNAME` error is tolerated (`""` + continue); HTTP fail with DNS ok is
  partial (`Result` + `HTTPError` preserving the first error, exit 0).

## Privacy and product scope (`DF-01=G`, not an agent rule)

- `GO-09` Raw `Set-Cookie` values are captured into `Result.Cookies` but
  rendered masked by default (`name=first4…last4`, attributes intact),
  full only under `--show-cookies` (ADR-0014); `--json` follows the same
  rule (masked unless the flag). Values never enter `Headers` (allowlist
  test guards). Responsible-use notice lives in the product
  (`README`/`SECURITY`/CLI help). The agent never refuses a scan task.

## i18n (`AC-02`)

- `GO-10` Every user string via `i18n.T` with EN+PT;
  `TestAllKeysHaveBothLangs` enforced; `Detect(flag,getEnv)` pure;
  fallback `EN` then `[missing:key]`, never `""`.

## Schemas and tests (`AC-02`, `EN-01`)

- `GO-11` JSON stable: initialized slices/maps (never `null`), both ports
  `80/443` always present, exact tags, `ErrorEnvelope{domain,error}`
  separate from `Result`.
- `GO-12` Table-driven tests, stdlib `testing` only, `Resolver`/`Fetcher`/
  `Dialer` interfaces, no real network except `localhost`, dynamic ports.

## Toolchain and workflow (`EN-02`, `AC-02`)

- `GO-13` `go 1.27`, `x/net v0.61.0`, `golangci-lint v2.4.0` pinned;
  `.golangci.yml` v2 with `goimports` under `formatters`, not `linters`.
- `GO-14` Work on `dev` only, atomic Conventional Commits with WHY bodies,
  green loop `gofmt → vet → test → race (if cgo) → golangci-lint`.

## Secrets mode and fixture hygiene (`AC-01`, `DF-01=C/G`)

- `GO-15` `--secrets` is a separate mode with its own contract:
  `SecretsResult` envelope separate from `Result`; values masked by
  default (`first4…last4`) with full value only under opt-in
  `--reveal`/`-rv`; `--reveal` without `--secrets` is exit `2`;
  `Finding.Pattern` gains values only via verified formats (ADR table).
  WHY: exit 3 drives conditional automation; masked-by-default keeps
  logs/videos pastable; the envelope split keeps the v1 schema stable.
- `GO-16` No committed line contains a complete realistic secret: long
  fakes are built at test runtime (deterministic seeds) or split across
  string boundaries; committed literals are public examples (`EXAMPLE`
  suffix, jwt.io token) or uniform filler. WHY: push protection flags
  partner shapes even when fake — a blocked push was the tuition fee.
