# PLAN.md — Primeiro Build do `gosomething` / `exposcan`

> **Status:** APPROVED v9 — QA `APROVADO (go)` com veredito efêmero em log de commit (QA-PLAN*.md temporários removidos; norma viva em `docs/qa-gate/`). Drift de toolchain documentado (winget `GoLang.Go 1.27.0` vs `go.dev 1.27.2`). Codagem liberada na `dev` com `go1.27.0`.
> **Data:** v1-v8 2026-10-11 / **v9 2026-10-11** (branch `dev`)
> **EN abstract:** Build plan v9 for `exposcan` in `gosomething`: Go 1.27 CLI (toolchain 1.27.0 installed via winget GoLang.Go; plan previously said 1.27.2 from go.dev — drift documented), 15s global, EN-US default + PT-BR, mocked table tests, minimal lint, docs + 7 ADRs, `go build` only, `dev`. Gate: DoR/DoD + §13 table.

**Nota:** PT-BR para revisão. Finais: CLI bilíngue default `en-US`, `README` EN + `README.pt-BR`, `AGENTS.md` EN puro, ADRs EN.

---

## 0. Mecanismo (vai para `AGENTS.md`)

### 0.1 Inegociáveis

1. **Omissão proibida** (só `[REDACTED: WHY]` para segredo/PII). Formato `Decisão + WHY + descartada + WHY`.
2. **WHY obrigatório.** Sem WHY = reprova.
3. **Webfetch obrigatório.** Assinatura só vale completa + link. Versão só vale com fonte + data. Verificadas nesta v9 em §2.
4. **Zero placeholder com aceite exato.** `...`, `vX`, `etc` no aceite = reprova.

### 0.2 Definition of Ready (plano só vai ao QA se)

- [x] Todo campo `Result`/`ErrorEnvelope` tem produtor → consumidor → teste
- [x] Assinaturas coladas + conversões (`a.IP`, `Timeout()`, `ContinueOnError`)
- [x] `run(args,getenv,stdout) int` com `NewFlagSet` + `SetOutput` + `Usage` custom (C1)
- [x] `isTimeout` via `os.IsTimeout` (C2), predicado fallback exato (M1)
- [x] `ErrOK` + map `idna→ErrCode` + `original` normalizado (C3)
- [x] Política parcial best-effort + qual JSON (C4)
- [x] CDN operadores + fixtures (M2), humano com contrato (M3)
- [x] `golangci` pinado + skeleton v2 (M4), detalhes JSON/rede (M5)
- [x] Lint incondicional + install no pré-req

### 0.3 Definition of Done

- [ ] `gofmt` vazio, `vet` limpo, `test` + `-race` verdes offline (logs)
- [ ] `golangci-lint run` limpo (instalação pré-req, sem condicional)
- [ ] `TestResult_JSONTags`, `TestErrorEnvelope_JSON`, `TestRun_Exits`, `TestFallback_Predicate`
- [ ] N commits atômicos `dev` + push; nada na `main`

### 0.4 Gate duplo

* Step-by-step (esta v9) + multi-agent proposto no build de código.

---

## 1. Decisões (WHY)

1. **Repo `gosomething`, tool `exposcan`, rename aberto → ADR-0001.** WHY: mix cybersec futuro incerto; churn agora pior.
2. **Global 15s chefe, internos `min()`.** WHY: invariante + cancelamento. Mapeamento real em §5.6: `isTimeout==true (DeadlineExceeded/os.IsTimeout/Timeout()) → err.timeout`; `context.Canceled → err.httpFail/dnsFail` genérico (não é timeout — fecha QA-v5 M2); resto → `err.httpFail/dnsFail`.
3. **Module `github.com/matheuslyam/gosomething`.** WHY: seu remote.
4. **Go `1.27.0` instalado via winget (`GoLang.Go`), `go.mod` declara `go 1.27`; `x/net v0.61.0`, `golangci v2.4.0` pinados.** WHY drift (v9): o plano dizia `1.27.2` (estável `go.dev/VERSION` 2026-10-02), mas o winget só serve `GoLang.Go 1.27.0` (verificado `winget search`); ID correto é `GoLang.Go`, não `Go.Go` (correção de erro meu no plano). `go 1.27` no mod cobre ambas; patch drift não afeta o build. Instalado e verificado: `go version go1.27.0 windows/amd64`.
5. **Bilíngue default `en-US`.** WHY: exigência + público. `Detect(flag,getEnv)` pura.
6. **`AGENTS.md` EN puro.** WHY: consumo LLM.
7. **Lint sem `revive`.** WHY: aprendizado; 4 linters (`govet/staticcheck/misspell/ineffassign`) + 1 formatter (`goimports`) via `golangci-lint v2`.
8. **Só `go build`.** WHY: pedido simples.
9. **Swagger deferrado → ADR-0007, `FIRST.md` intocado.** WHY: sem API HTTP.
10. **Pessoal + público com `MIT+CoC+CONTRIBUTING+SECURITY`.** WHY: `FIRST.md:16+20`.
11. **LICENSE `MIT 2026 matheuslyam`, contato `matheuslyambusiness@gmail.com` em `SECURITY.md` E `CODE_OF_CONDUCT.md`.** WHY: Covenant exige canal (M5 fechado).
12. **SSRF sem bloqueio, aviso + redirect≤3.** WHY: baixo risco, aprendizado.
13. **Headers valores `server/x-powered-by/via/cf-ray/x-amz-cf-id`, `set-cookie` só presença.** WHY: sua ruling; valor é o sinal.
14. **HTTPS → fallback HTTP só em falha rede/TLS, nunca em status.** WHY: sua ruling; predicado exato §5.6 (M1).
15. **Parcial = best-effort com `Result` parcial + `warnings`.** WHY: decisão C4 abaixo — abortar tudo em HTTP fail perderia DNS/ports já coletados; envelope de erro só quando nada aproveitável (DNS fail total) ou uso inválido.

## 2. Ambiente verificado

* **Go:** plano previa `go1.27.2 2026-10-02` via `https://go.dev/VERSION?m=text`; **instalado `go1.27.0 windows/amd64`** via `winget install --id GoLang.Go` (única versão servida). **x/net `v0.61.0 2026-10-09`** via `pkg.go.dev/golang.org/x/net/idna` (`ToASCII(s)(string,error)`, `Lookup`).
* **Verificadas hoje via `pkg.go.dev`:**
  * `flag.NewFlagSet(name string, errorHandling ErrorHandling) *FlagSet` + `const ContinueOnError, ExitOnError` + `func (f *FlagSet) SetOutput(io.Writer)` + `func (f *FlagSet) Parse([]string) error` + `var ErrHelp`. WHY C1: default `CommandLine` usa `ExitOnError` → `os.Exit` no teste; `ContinueOnError` retorna erro.
  * `net/url.Error{Op,URL,Err} + func Timeout() bool + Unwrap() error`; `net.OpError` com `Timeout() bool`; `os.IsTimeout(err) bool`. WHY C2: `Client.Timeout` e `Dial` embrulham em tipos com `Timeout()==true`, não `DeadlineExceeded`; só `os.IsTimeout` + `errors.As` com interface `Timeout() bool` pega todos.
  * `net.Resolver.LookupIPAddr(ctx,host)([]net.IPAddr,error)`, `LookupCNAME(ctx,host)(string,error)`; `Dialer.DialContext(ctx,network,address)(net.Conn,error)`.
* **Git:** `main=README.md(14b5f9b)`; em `dev`; untracked `FIRST/PLAN/QA-PLAN*`.
* **Pré-req (incondicional — Go + golangci OK nesta v9):**
  ```powershell
  chcp 65001
  winget install --id GoLang.Go --silent --accept-package-agreements --accept-source-agreements
  "C:\Program Files\Go\bin\go.exe" version
  "C:\Program Files\Go\bin\go.exe" install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0
  golangci-lint version
  ```
  Instalado v9: `go version go1.27.0 windows/amd64` (via caminho completo — `PATH` da sessão manda refresh; reabra o terminal ou use `"C:\Program Files\Go\bin\go.exe"`) + `golangci-lint 2.4.0` (`%USERPROFILE%\go\bin\golangci-lint.exe`, verificado nesta v9). WHY log obrigatório (fecha QA-v5 M4): `golangci-lint version` sai no resumo do build — pin sem log é alegação.

## 3. Objetivo

```bash
go build -o exposcan ./cmd/exposcan
./exposcan example.com
./exposcan --lang pt exemplo.com
./exposcan --json --timeout 10s example.com
./exposcan --help
./exposcan --lang pt --help
```

EN `example.com`/PT `exemplo.com`. 1 FQDN; single-label rejeitado. Output §5.9 + humano §5.10. Exits §5.2.

## 4. Árvore

```
.gitignore (primeiro)
FIRST.md (histórico, intocado)
PLAN.md (este; APPROVED em commit próprio)
README.md / README.pt-BR.md (sem badges) / CONTRIBUTING.md / CHANGELOG.md
LICENSE / CODE_OF_CONDUCT.md (com contato) / SECURITY.md
AGENTS.md / .golangci.yml (skeleton §4.1) / go.mod / go.sum
cmd/exposcan/main.go + main_test.go
internal/i18n/i18n.go + i18n_test.go
internal/validate/domain.go + domain_test.go
internal/dns/resolver.go + resolver_test.go
internal/httpfetch/fetcher.go + fetcher_test.go
internal/ports/checker.go + checker_test.go
internal/cdn/detect.go + detect_test.go
internal/exposcan/scan.go + scan_test.go
docs/adr/0001…0007 / docs/architecture.md
```

### 4.1 `.golangci.yml` skeleton v2 (fecha QA-v5 C2)

```yaml
version: "2"
linters:
  enable:
    - govet
    - staticcheck
    - misspell
    - ineffassign
formatters:
  enable:
    - goimports
run:
  timeout: 3m
```

WHY `version:"2"` + `goimports` em `formatters`: na v2 `goimports` é formatter (`golangci-lint help formatters`), não linter — verificado hoje em `golangci-lint.run/docs/formatters`. Colocar em `linters.enable` quebra o run. WHY esses 4+1: erro real sem opinião (`revive` fora intencional).

## 5. Especificação

### 5.1 `go.mod`

`module github.com/matheuslyam/gosomething` / `go 1.27` / `require golang.org/x/net v0.61.0`.

### 5.2 `main.go` (fecha QA-v5 C1, G1, C4/G2/G3)

```go
func peekLang(args []string) string // varre args: "--lang pt" ou "--lang=pt" → "pt", senão ""
func run(args []string, getenv func(string) string, stdout io.Writer) int
func main() { os.Exit(run(os.Args[1:], os.Getenv, os.Stdout)) }
func realDeps(global time.Duration) exposcan.Deps // NetResolver + HTTPFetcher{min(10s,global)} + PortDialer{min(5s,global)}
```

* `run`: `langFlag := peekLang(args)` (aceita `--lang pt` e `--lang=pt`; ausente → `""`; valor fora `en|pt` → tratado depois como `err.badLang`); `lang := Detect(langFlag, getenv)`; `fs := flag.NewFlagSet("exposcan", flag.ContinueOnError)`; `fs.SetOutput(stdout)`; `fs.Usage = func(){ fmt.Fprintf(stdout, i18n.T(lang,"usage")) ; fs.PrintDefaults() }`. WHY peek (fecha QA-v5 G1): `Usage` precisa da lang antes do parse completo; peek manual é só para idioma da mensagem/`Usage`, não para aceitar flag fora de ordem.
* Exits (fecha QA-v5 C1): `errors.Is(err, flag.ErrHelp)` → `Usage` em `stdout` + `return 0`. Parse-erro real → `stdout` + `return 2`. Flag inválida (`badTimeout/badLang`) → `return 2`.
* Regra NArg (fecha QA-v6/v7 — 1 FQDN exato): após `fs.Parse(args)`, `if fs.NArg() != 1 → ErrorEnvelope{Domain: Arg(0) se existir senão "", Error: T(lang,"err.noDomain")} → return 2; arg := fs.Arg(0)`. Travado: chave sempre `err.noDomain` (nunca `usage` solto — `Usage` já foi impresso via `SetOutput` no parse-erro; aqui é erro de uso com envelope); `Domain = fs.Arg(0)` quando `NArg>=1` (caso 2+ args usa o 1º só para eco), `""` quando `NArg==0`. WHY: `0 args` e `2+ args` ambos reprovam; flag após posicional tem `NArg=3` → `2` mesmo que `peekLang` ache `pt` (peek só idioma).
* `ValidateDomain` erro → `ErrorEnvelope` → `return 2`.
* `Scan` — parcial best-effort com regra fatal explícita (fecha G2/C4): `LookupIPs` erro → fatal → `ErrorEnvelope` + `return 1` (DNS total fail = sem IPs, nada aproveitável). `LookupCNAME` erro → tolera (`CNAME=""` + segue, exit ainda pode ser 0). HTTP fail → nunca fatal se DNS ok → `Result` parcial (ver §5.9). `run`: `error!=nil → ErrorEnvelope` (exit 1); `error==nil → Result` (exit 0) mesmo com `HTTPError` (parcial = 0 + warnings).
* Fallback preserva primeiro erro (fecha G3): `https` falha com `shouldFallbackToHTTP==true` → tenta `http`; se `http` ok, `HTTPError` guarda `"https: <primeiro-erro>"` como warning visível (não `""` silencioso — WHY: downgrade cert→http escondido é risco de segurança); `Status/FinalURL` refletem o `http`, `HTTPError` reflete o `https`.

```go
type ErrorEnvelope struct { Domain string `json:"domain"`; Error string `json:"error"` }
```

WHY sem `Lang`: erro já localizado.

### 5.3 `i18n`

`Detect(flag,getEnv) Lang` + `T(l,key,args...) string`. Fallback: ausente → EN; EN ausente → `[missing:key]`. Chaves §v9 + `err.singleLabel`. `TestAllKeys + TestT_Fallback`.

### 5.4 `validate` (fecha C3, M1, M7)

```go
type ErrCode string
const (
  ErrOK ErrCode = ""
  ErrEmpty = "empty"; ErrTooLong = "tooLong"; ErrLabelTooLong = "labelTooLong"
  ErrBadChars = "badChars"; ErrSingleLabel = "singleLabel"; ErrInvalid = "invalid"
)
func ValidateDomain(input string) (original, ascii string, code ErrCode)
```

* `original` normalizado = `TrimSpace` + remove **um** `.` final (fecha M1: `Domain` nunca exibe com ponto; `example.com.` → `example.com`). Mantém case original. `ascii` = `idna.Lookup.ToASCII` + checks.
* Sucesso = `ErrOK ("")`.
* Ordem real travada (fecha G4): `TrimSpace → remove 1 dot → vazio? → contém "."? (não → ErrSingleLabel imediato, antes do idna)` → `idna.Lookup.ToASCII` (erros → `ErrBadChars`) → `len>253?/label>63?` → `charset/bordas/..`. WHY `SingleLabel` antes do `idna`: `bad_domain!` sem ponto deve dizer "use FQDN" (`SingleLabel`), não "chars inválidos"; checar ponto primeiro dá mensagem mais útil e determinística.
* Dot rule (M1): remove **um** `.` final uma vez; se ainda termina com `.` ou contém `..` → `ErrBadChars`.

### 5.5 `dns`

`LookupIPs` via `LookupIPAddr` + loop `a.IP` (conversão obrigatória). Mock fixo/erro. `IPs` saída via `ip.String()` (fecha M5).

### 5.6 `httpfetch` (fecha C2, M1, M6)

```go
type HTTPResult struct { Header http.Header; Status int; FinalURL string }
type Fetcher interface { Fetch(ctx context.Context, url string) (HTTPResult, error) }
func isTimeout(err error) bool {
  if err == nil { return false }
  if errors.Is(err, context.DeadlineExceeded) { return true }
  // context.Canceled NÃO é timeout (é cancelamento manual) — fecha M2: não mapear para err.timeout;
  // Canceled cai em err.httpFail/dnsFail genérico, mas mantém exit 1. Só DeadlineExceeded vira err.timeout aqui.
  if os.IsTimeout(err) { return true } // pega *url.Error{Timeout:true} + *net.OpError{Timeout:true} — verificado pkg.go.dev
  var te interface{ Timeout() bool }
  if errors.As(err, &te) && te.Timeout() { return true }
  return false
}
func shouldFallbackToHTTP(err error) bool { // fecha M1 — predicado exato, nunca status
  if err == nil { return false }
  if isTimeout(err) { return true }
  if errors.Is(err, syscall.ECONNREFUSED) { return true } // via errors.As unwrapping OpError/Syscall
  var certErr *tls.CertificateVerificationError
  var unknownAuth x509.UnknownAuthorityError
  if errors.As(err, &certErr) || errors.As(err, &unknownAuth) { return true }
  var tlsErr *tls.RecordHeaderError
  if errors.As(err, &tlsErr) { return true }
  return false // 404/500/status nunca caem aqui (estão em HTTPResult, não em err)
}
```

Real: `Client{Timeout: min(10s,global), CheckRedirect: ≤3 → ErrUseLastResponse}` + `NewRequestWithContext(GET)` + `UA` + `LimitReader 1MB` + `Close`. `FinalURL` = última URL após redirects (com `ErrUseLastResponse` = URL do 3º redirect, documentado — fecha M5). Mapeamento: `isTimeout→err.timeout` senão `err.httpFail`.

### 5.7 `ports`

`Open(ctx,hostport) bool` + `Close`. `80+443` paralelo. Teste dinâmica. Inicialização `Ports` sempre com ambas chaves `80,443` (mesmo false) — fecha M5 (JSON estável).

### 5.8 `cdn` (fecha M2)

Lower uma vez (`cnameL`, `Header.Get` canoniza — WHY: `Get` já case-insensitive). Operadores exatos:

* CNAME todos com `HasSuffix(cnameL, ".<provider>.net/.com")` (fecha M3 — sem `Contains` genérico): `.cloudflare.net`, `.cloudfront.net`, `.akamai.net`, `.akamaized.net`, `.fastly.net`, `.sucuri.net`, `.incapsula.com`, `.ddos-guard.net`. WHY sufixos também para Akamai: `Contains(cname,"akamai")` dá falso-positivo em `notakamai.com`.
* Header via `h.Get(...)` (canoniza `Cf-Ray`): presença para `Cf-Ray/X-Amz-Cf-Id/X-Sucuri-Id/X-Iinfo/X-Ddos-Guard`; `X-Served-By` com `strings.Contains(strings.ToLower(v), "cache-")` (Contains documentado — CDN varia prefixo).

### 5.9 `scan` (fecha B1,B2,C4,G4,M5)

```go
type Deps struct { DNS Resolver; HTTP Fetcher; Dial Dialer }
type Result struct {
  Domain string `json:"domain"`; Punycode string `json:"punycode"`
  IPs []string `json:"ips"`; CNAME string `json:"cname"`; CDN string `json:"cdn"`
  Ports map[int]bool `json:"ports"`; Headers map[string]string `json:"headers"`
  HSTS bool `json:"hsts"`; CSP bool `json:"csp"`
  HasSetCookie bool `json:"hasSetCookie"`; ServerPresent bool `json:"serverPresent"`
  HTTPStatus int `json:"httpStatus"`; FinalURL string `json:"finalUrl"`; HTTPError string `json:"httpError,omitempty"`
}
func Scan(ctx context.Context, domain, punycode string, deps Deps) (Result, error)
```

* Inicialização (M5): `IPs=[]string{}` (nunca null), `CNAME=TrimSuffix(cname,".")`, `Ports={80:false,443:false}`, `Headers={}` allowlist `server,x-powered-by,via,cf-ray,x-amz-cf-id` (valores; `set-cookie` nunca entra). `HSTS/CSP` avaliados só se `FinalURL` scheme https, senão `false` explícito.
* Ordem: `DNS(LookupIPs fatal; CNAME tolera "") → HTTP(https://punycode; se shouldFallbackToHTTP(err) → http://, preservando primeiro erro em HTTPError) → Detect → ports`. `Status/FinalURL` de `HTTPResult` alimentam flags.

### 5.10 Humano (fecha M3)

Contrato mínimo (testado por `TestHuman_ContainsKeys`, não snapshot frágil): linhas `k: v` para `domain, punycode, ips, cname, cdn, ports 80/443, hsts, csp, server` + seção `headers:` + `warnings:` se `HTTPError`. WHY não snapshot total: i18n muda texto; teste checa chaves, não frase.

## 6. Testes

`validate` 15 + `ErrCode` map + `original` preservado; `i18n` keys + fallback; `cdn` 7/7 fixtures com operadores; `dns/http/ports` mocks + dinâmica; `scan` Success/DNSFail(CNAME-tolerado)/Timeout/HTTPFallback(partial Result+HTTPError preservado)/HeadersAllowlist; `main` via `run` (`TestRun_HelpReturns0`, `TestRun_ParseErrReturns2`, `TestRun_NArg` [0 args→2, 2+ args→2, flag após posicional→2], exits, envelope); `TestResult_JSONTags`, `TestErrorEnvelope_JSON`, `TestIsTimeout_Matrix` (`DeadlineExceeded/url.Timeout/OpError.Timeout→true`, `Canceled→false`), `TestShouldFallback` (refused/TLS/timeout→true, 404→false), `TestPeekLang` (`--lang pt`, `--lang=pt`, ausente, inválido). Offline; rede demo manual.

## 7–10. AGENTS/docs/FORA

`AGENTS.md` EN com §0 + DoR/DoD + `isTimeout/shouldFallback/run/peekLang/NArg` patterns. Docs/ADRs 7. FORA mantido desde v6.

## 11. Workflow

Pré-req §2. `dev`: `.gitignore` → `go.mod` → `i18n→validate→cdn→dns/http/ports→scan→run/main` → testes → docs. Loop verde. N commits + push. `PLAN→APPROVED` próprio.

## 12. Aceite (incondicional)

`gofmt` vazio, `vet` limpo, `test`+`race` verdes, `golangci` limpo **obrigatório** (com `golangci-lint version` logada), `--help` retorna `0` EN/PT, parse-erro retorna `2`, `NArg!=1` retorna `2`, JSON válido por teste, exits, `T()` fallback, CDN 7/7, humano com chaves, nada `main`.

## 13. Self-QA v9 — regra → status → evidência (veredito efêmero; QA-PLAN*.md temporários removidos, norma viva em `docs/qa-gate/`)

| ID | Regra | Status | Evidência |
|---|---|---|---|
| NArg | IF após `Parse` THEN `NArg!=1 → 2` (`err.noDomain`; `Domain=Arg(0)` ou `""`); peek só idioma | PASS | §5.2 regra + `TestRun_NArg`; WHY ordem fixa |
| Tree | IF arquivo existe THEN está na árvore | PASS | §4 lista só docs vivos (QA-PLAN*.md temporários removidos) |
| C1 | IF `--help` THEN `0`; parse-erro THEN `2` | PASS | §5.2 (mantido) |
| C2 | IF v2 THEN `goimports` em `formatters` | PASS | §4.1 + fetch formatters |
| G1-G4 | peek/DNS-fatal/first-error/SingleLabel | PASS | §5.2/§5.4/§5.9 (mantidos) |
| M1-M4 | original/Canceled/Akamai/version-log | PASS | §5.4/§5.6/§5.8/§2+§12 (mantidos) |
| DoR | 9+7 itens | PASS | ticks §0.2 + NArg |

---

**QA `APROVADO (go)` — alvo era este arquivo (v9). Toolchain confirmada na `dev`, codagem em curso.**
