# QA — `PLAN.md` v4 — VEREDITO: **REPROVADO (por pouco)**

Evolução real: B1-B3/G1-G4/M1-M5/M7-M8 da v3 estão fechados. `14b5f9b` confere, `dev` ativa, `x/net v0.61.0` confere. Mas o self-QA §13 marcou `PASS` onde há bug — 4 itens impedem o `go`.

## Bloqueadores

**C1. `run() int` testável é falso com `flag` padrão** — `PLAN.md:121-127`
`run(args,getenv,stdout) int` + `main_test` não funciona se usar `flag` default (`CommandLine`, `ExitOnError`). Parse error e `--help` chamam `os.Exit` direto, matam o teste e ignoram `stdout`. Falta travar:
`flag.NewFlagSet(..., ContinueOnError)` + `fs.SetOutput(stdout)` + `Usage` custom. Sem isso, B3 do §13 é `FAIL`.

**C2. Mapeamento timeout incompleto** — `PLAN.md:49,175,259`
`errors.Is(err, context.DeadlineExceeded/Canceled) → err.timeout` não pega o caso real:
`http.Client{Timeout}` retorna `*url.Error{Timeout:true}`, `Dial` retorna `net.OpError{Timeout:true}` — nenhum é `DeadlineExceeded`. Vão cair em `err.httpFail` com mensagem errada. Tem que ser `os.IsTimeout(err) || errors.As(...Timeout()))`. M6 marcado `PASS` está errado.

**C3. `ValidateDomain` sem sentinel de sucesso + sem map de erro `idna`** — `PLAN.md:144-147`
`(original, ascii string, code ErrCode)` com 6 consts de erro, mas válido retorna o quê? `""`? Falta `ErrOK` ou regra `""=ok`. E `idna.Lookup.ToASCII` falha (runa proibida, bidi, hífen) → qual `ErrCode`? `ErrBadChars` vs `ErrInvalid` indefinido. `original` normalizado como? (`TrimSpace`? mantém case?). Implementador vai adivinhar, `TestErrCodeToI18n` diverge.

**C4. Política de falha parcial indefinida** — `PLAN.md:126,211,217,221`
`Scan→(Result,error)`, `run→0/1`. Se DNS ok + HTTP fail + ports ok: retorna `Result` parcial ou `ErrorEnvelope`? Aborta ou segue best-effort? `Status/FinalURL` decidem flags, mas qual JSON vai ao `--json` no erro? Testes `Success/DNSFail/Timeout/HTTPFallback` não dizem envelope vs result. Afeta exit + schema.

## Médias (viram bug na implementação)

**M1. Gatilho do fallback vago** — `PLAN.md:61,217`
`só se err for timeout/connection-refused/TLS — não em status`. Como detecta? `syscall.ECONNREFUSED` via `errors.As`, `tls.CertificateVerificationError`, `x509.UnknownAuthority`? Sem predicado exato, `TestHTTPFallback` é flaky.

**M2. Matcher CDN sem operador** — `PLAN.md:183-194`
Tabela exata é avanço, mas falta operador: CNAME é `HasSuffix`? Header `akamai-*` é `HasPrefix`? `x-served-by: cache-` é `Contains` case-insensitive? `http.Header` canoniza (`Cf-Ray`) — usa `Get` ou lower manual? Sem isso, 7/7 passa no teste e falha no mundo.

**M3. Output humano sem contrato** — `PLAN.md:89,126`
JSON tem tags exatas, humano não tem formato nem teste. `§0.1.1` (omissão proibida) exige ao menos referência (ex: `k: v` por linha). Hoje §12 só cobra `--help` + JSON.

**M4. Pin furado + config ausente** — `PLAN.md:74,99`
`go install .../golangci-lint/v2/cmd/golangci-lint@latest` flutuante contradiz filosofia de pin (`v0.61.0` exato). Pinar versão + colar esqueleto `.golangci.yml` v2 (chave `version: "2"`, 5 linters). Sem isso, `golangci-lint run limpo` é inverificável.

**M5. Detalhes JSON/rede omitidos** — `PLAN.md:202-209,217`
`Ports` sempre tem `80,443`? `IPs` via `IP.String()`? `CNAME` com trailing dot trimado? `FinalURL` com `ErrUseLastResponse` é qual URL? `HSTS/CSP` em fallback http = `false` explícito? Pequenos, mas quebram `TestResult_JSONTags`.

## Para v5 passar

1. §5.2: `NewFlagSet(ContinueOnError)+SetOutput+Usage`, `realDeps(global)` explícito, regra parcial (best-effort vs fail-fast + qual JSON).
2. §5.6: `isTimeout(err)` via `os.IsTimeout/As`, predicado fallback exato (`ECONNREFUSED/TLS/timeout`, nunca status).
3. §5.4: `ErrOK`/vazio documentado, map `idna err → ErrCode`, `original` normalizado.
4. §5.8: operadores (`HasSuffix/HasPrefix/Contains`, lower onde), §5.9: inicialização `Ports/IPs/CNAME`, pin `golangci`, formato humano mínimo.

Self-QA §13 errou em M6/C1 — sinal de que `step-by-step` não pega taxonomia de erro stdlib; para v5, rode webfetch em `net/url.Error + net.OpError Timeout` antes de marcar `PASS`.