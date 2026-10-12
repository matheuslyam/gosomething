# QA — `PLAN.md` v5 — VEREDITO: **REPROVADO (narrow, 2 quebras reais)**

v5 fecha C2-C4/M1-M5 no essencial. Restam 2 quebras de build/comportamento + 4 gaps que voltam a adivinhação.

## Bloqueadores

**C1. `--help` retorna `2`, deveria `0`** — `PLAN.md:145`
`Parse erro ou ErrHelp → stdout + return 2`. `ErrHelp` (usuário pediu `--help`) não é erro — convenção é `0`. Do jeito atual, `./exposcan --help` passa no texto e falha no exit. Corrigir: `ErrHelp → return 0`, parse-err/inválida → `2`.

**C2. Skeleton `golangci` inválido na v2** — `PLAN.md:115-126`
`goimports` em `linters.enable`. Na v2, `goimports` é **formatter** (`golangci-lint help formatters`: `gofmt/gofumpt/goimports/gci/golines`), não linter. Verificado hoje em `golangci-lint.run/docs/formatters` vs `/linters` (lista sem `goimports`). `golangci-lint run` falha com linter desconhecido. Corrigir:
```yaml
version: "2"
linters: {enable: [govet, staticcheck, misspell, ineffassign]}
formatters: {enable: [goimports]}
```

## Graves (lógica incompleta)

**G1. Peek `--lang` indefinido** — `PLAN.md:144`
`parse --lang primeiro com peek manual` — como? `--lang pt` vs `--lang=pt` vs ausente vs inválido? Sem função `peekLang(args) (flagVal, rest)` travada, `Usage` bilíngue usa lang errada e `TestRun_Exits` diverge.

**G2. `DNS total fail` sem definição** — `PLAN.md:148,237`
`error!=nil só em DNS total fail / timeout`. `LookupIPs` fail = total? `LookupCNAME` fail tolera (vazio)? Se CNAME falhar e IPs ok, é `Result` parcial `exit 0` ou envelope `exit 1`? Travar: `IPs err → fatal; CNAME err → "" + segue`.

**G3. Fallback bem-sucedido apaga o primeiro erro** — `PLAN.md:148,231,237`
`https` falha cert/timeout → `http` ok. `HTTPError` fica `""` (sucesso limpo) ou guarda `https: <err>` em warnings? Segurança: downgrade cert→http silencioso esconde problema. Travar: `HTTPError` preserva primeiro erro mesmo com fallback ok (warnings visível, `exit 0`).

**G4. Precedência `SingleLabel` contradiz ordem** — `PLAN.md:175-176`
Diz `sem ponto → ErrSingleLabel prevalece (checado antes do idna)`, mas ordem lista `exige ponto` por último (após `idna`). Para `bad_domain!` sem ponto: `BadChars` ou `SingleLabel`? Travar ordem real: checar `strings.Contains(trimmed,".")` antes do `idna` para priorizar `SingleLabel`.

## Médias

- **M1. `original` com trailing dot** — `PLAN.md:173`: `original=TrimSpace` mantém case, mas e `"example.com."`? `Domain` exibe com ponto e `Punycode` sem? Travar `original` também sem 1 dot final.
- **M2. `Canceled → timeout` impreciso** — `PLAN.md:187-194`: `context.Canceled` não é timeout (é cancelamento manual). Ambos `exit 1`, mas mensagem `err.timeout` mente. Separar ou mapear `Canceled → err.httpFail/dnsFail` genérico.
- **M3. Akamai `Contains` vs sufixo** — `PLAN.md:218-219`: demais usam `HasSuffix(.xxx.net)`, Akamai admite `Contains(cname,"akamai")` — `notakamai.com` vira falso-positivo. Usar sufixos também.
- **M4. `v2.4.0` não verificada aqui** — `PLAN.md:50,76`: fallback "travar instalada" ok, mas aceite exige confirmar `golangci-lint version` logada no resumo (senão pin é alegação).

## OK verificado

- `isTimeout` com `os.IsTimeout + As(Timeout())` correto; `ECONNREFUSED/TLS/RecordHeader` predicado testável; `ContinueOnError+SetOutput` presente; `ErrOK=""`, `idna→BadChars`, `Ports{80,443}`, `IPs=[]`, `CNAME TrimSuffix`, `FinalURL/HTTPStatus`, humano `k: v` + teste chaves, `QA-PLAN-v4.md` existe e árvore confere.

Para v6: corrigir C1+C2 (2 linhas), travar G1-G4 (4 frases). Aí é `go`.