# Novo QA

Veredito: **REPROVADO de novo — mas por 3 coisas, não 30.** A v3 corrigiu B1-B8/G1-G7/I1-I18 na maioria. Restam 3 bloqueadores novos introduzidos na correção + 8 pendências menores.

Verificado e OK nesta v3:
- `go1.27.2 / 2026-10-02` confere, `x/net v0.61.0 / 2026-10-09` confere (`pkg.go.dev` hoje), `idna.Lookup.ToASCII` existe.
- `.git/HEAD` → `dev`, `refs/heads` tem `dev+main` — B4 corrigido.
- `winget install --id Go.Go -v`, `chcp 65001`, `.gitignore` primeiro + `/exposcan.exe`, `N commits`, `APPROVED` em commit próprio, `unknown` único, `Detect(flag,getEnv)`, sem `ToLower` — tudo certo.

## Bloqueadores novos

**B1. `Scan` perdeu o `Domain` original** — `PLAN.md:132` vs `PLAN.md:65,131`
`func Scan(ctx, punycode string, deps Deps)` + `Result{Domain, Punycode}`. Só com `punycode` não dá para preencher `Domain` (`münchen.de` vs `xn--mnchen-3ya.de`). A correção do B8 antigo criou bug novo. Tem que ser `Scan(ctx, domain, punycode string, ...)` ou `Scan(ctx, input ValidatedDomain, ...)`.

**B2. `Result` sem `Headers` vs §3 prometendo headers** — `PLAN.md:65` vs `PLAN.md:131`
§3 promete `headers + HSTS/CSP`. `Result` v3 só tem `HSTS, CSP, HasSetCookie, ServerPresent bool` — sem `Headers map` nem valores de `Server/X-Powered-By`. Ou o output humano/JSON não mostra valor nenhum (contradiz `FIRST.md:8` "headers sensíveis"), ou falta campo. Presença ≠ valor; decidir e travar.

**B3. `main_test.go` intestável** — `PLAN.md:84,102,138`
`Só main faz os.Exit` + `main_test.go: flags/exits` sem `run() -> int`. Não se testa `exit 0/1/2` chamando `main()` direto (morre o processo de teste). Falta especificar `func run(args []string, getenv, stdout) int` separado, `main` só chama `os.Exit(run(...))`.

## Graves / lógica restante

**G1. Fallback HTTPS sumiu** — `PLAN.md:134` vs v1 `PLAN.md` antigo
v1 tinha `https://, fallback http://`. v3 diz só `DNS→HTTP→Detect→ports`, §5.6 `Fetch(ctx, url)` sem dizer quem monta a URL. Site só-HTTP falha? Ou tenta as duas? Sem regra, `HSTS/CSP` e `ServerPresent` ficam ambíguos.

**G2. `Fetch` perde status/scheme** — `PLAN.md:120`
Retorna só `(http.Header, error)`. Sem `status code` e sem `scheme efetivo` não dá para distinguir `site fora` vs `404 com headers` vs `http fallback`. Precisa `type HTTPResult{Header, Status, FinalURL}` ou documentar descarte.

**G3. `LookupIPAddr` retorna `[]IPAddr`, não `[]IP`** — `PLAN.md:117`
Uso de `LookupIPAddr(ctx,host)` está certo para fugir do `network` (B1 antigo OK), mas a conversão `IPAddr→IP` (`a.IP`) não está no plano. Detalhe pequeno que quebra compilação se omitido.

**G4. Schemas JSON indefinidos** — `PLAN.md:102,131,158`
`Result json:"..."` placeholder + `ErrorEnvelope{Domain, Error, Lang}` sem tags/tipos. Aceite `PLAN.md:158` cobra `JSON schemas válidos` — inverificável sem schema fechado. `Lang` no envelope é redundante (erro já localizado)? Travar campos exatos.

## Médias (impedem "impecável")

- **M1. `validate` trailing dot singular** — `PLAN.md:108`: `remove "." final` — e `"example.com.."`? Um ou todos? Travar `TrimSuffix` em loop ou único.
- **M2. `T()` sem fallback** — `PLAN.md:105`: chave faltante retorna o quê? `""`, `key`, fallback EN? Sem regra, `TestAllKeys` não garante runtime.
- **M3. CDN sem matchers exatos** — `PLAN.md:126`: 7 nomes sem sufixos CNAME/valores header exatos + case-insensitive? Teste `7/7` precisa fixtures travadas.
- **M4. Gate condicional** — `PLAN.md:158`: `golangci limpo se instalado` = passa sem lint se não instalado. Ou exige install no pré-req ou tira do aceite.
- **M5. `CoC` sem contato** — `PLAN.md:80`: `SECURITY.md` tem `matheuslyambusiness@gmail.com`, `CODE_OF_CONDUCT.md` não. Covenant exige canal de denúncia.
- **M6. Duplo timeout** — `PLAN.md:120,123`: `Client{Timeout:min(10s,global)}` + `ctx global`. Qual erro vira `err.timeout` vs `err.httpFail`? Mapeamento ausente.
- **M7. `ErrCode` sem valores** — `PLAN.md:108`: `Retorna (ascii, ErrCode)` sem enumerar (`ErrEmpty/ErrInvalid/ErrSingleLabel/...`). Tabela `ErrCode→i18n` citada mas não listada.
- **M8. `--help` bilíngue sem forma** — `PLAN.md:158`: é `./exposcan --help` + `./exposcan --lang pt --help`? Ordem de flags não travada.

## Para virar v4 e passar

1. `Scan(ctx, domain, punycode string, deps)` + `Result` com ou sem `Headers` (decidir presença vs valor) + JSON tags exatas + `ErrorEnvelope` exato.
2. Especificar `run() int` + `main_test` via `run`, construção da URL (https-only ou fallback), `HTTPResult` com status/finalURL, conversão `IPAddr→IP`.
3. Travar M1-M4 (dot, fallback i18n, matchers CDN, lint obrigatório ou removido do aceite).

Fora isso, v3 está muito acima da v1. Não é `go` ainda.
s