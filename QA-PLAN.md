# QA — `D:\coding\projects\gosomething\PLAN.md` — VEREDITO: **REPROVADO**

Não aprove. Tem erro que nem compila, contradição de ordem, workflow git impossível e conflito direto com o `FIRST.md`.

## Bloqueadores (impedem build / aceite)

**B1. Interface DNS não compila** — `PLAN.md:109`
`LookupIP(ctx, host)` está errado. `net.Resolver.LookupIP` exige `(ctx, network, host)`. Do jeito especificado, `NetResolver` real não implementa nada.

**B2. Assinatura `Scan` inválida** — `PLAN.md:121`
`func Scan(ctx context.Context, domain, punycode string, deps Deps) (Result, error) onde Deps{ DNS; HTTP; Dial }` — `Deps` sem tipos não é Go válido. Falta definir os tipos dos 3 campos.

**B3. Ordem contraditória** — `PLAN.md:122`
`Ordem: DNS → CNAME → CDN (após HTTP) → HTTP headers` — CDN não pode vir antes e após HTTP ao mesmo tempo. Impossível implementar como escrito.

**B4. Workflow git impossível** — `PLAN.md:166`
`manter main vazia para PR` + `todo código na dev`. Não existe PR contra branch vazia sem commit inicial. Falta commit raiz na `main` (ex: `README` + `LICENSE`) antes da `dev`.

**B5. `Result` vs JSON de erro incompatíveis** — `PLAN.md:95` vs `PLAN.md:121`
`main` promete `{"domain":...,"error":...}` no `--json`, mas `Result` não tem campo `error`. Schema JSON indefinido / contraditório.

**B6. Validação com ordem errada** — `PLAN.md:104`
Checa `len>253` **antes** de `idna.ToASCII`. Punycode expande (`münchen.de` → `xn--...`). Checagem correta é no ASCII final. Do jeito atual, domínio longo pós-punycode passa quando não deveria.

**B7. Teste de porta local impossível** — `PLAN.md:133`
`listener 127.0.0.1:0 para teste real` + `checa 80 e 443`. Listener `:0` pega porta aleatória, nunca 80/443 sem root. Teste como descrito sempre falha. Falta parametrizar `hostport` no checker.

**B8. Teste na camada errada** — `PLAN.md:132`
`TestScan_InvalidSkipsNetwork (garante zero chamadas)` — mas `Scan` recebe `domain, punycode` já validados. Inválido nunca chega no `Scan`. Esse teste é vazio; pertence ao `validate`, não ao `Scan`.

## Graves (lógica / segurança)

**G1. Timeout incoerente** — `PLAN.md:13,115`
Global `15s`, mas `http.Client{Timeout:10s}` + `Dialer{Timeout:5s}` sequenciais (DNS→HTTP→ports) somam ~20s. Com `--timeout 5s`, o HTTP interno (10s) é maior que o global. Fala qual manda, falta timeout por etapa.

**G2. HTTP baixa corpo inteiro** — `PLAN.md:112`
`GET + fecha body + retorna só header (não baixa corpo além do necessário)` é contraditório. `GET` baixa. Sem `HEAD`, sem `MaxBytes`/`LimitReader`, alvo malicioso retorna 10GB e dá OOM. Também falta: `User-Agent`, limite de redirect, `InsecureSkipVerify=false` explícito.

**G3. Leak de conexão + perda de erro** — `PLAN.md:115`
`Open(ctx, hostport string) bool` perde motivo (closed vs timeout vs DNS). E não menciona `Close()` da `conn` do `DialContext` — leak de FD.

**G4. Vazamento de `Set-Cookie`** — `PLAN.md:125` vs `PLAN.md:121`
Diz `Set-Cookie (só presença)`, mas `Headers map[string]string` guarda valor. Se logar valor, vaza sessão no output/JSON. Tem que ser `bool` ou lista de nomes, nunca valor.

**G5. SSRF / alvo interno sem regra** — `PLAN.md:43,115`
Nenhuma política para `127.0.0.1`, `10/8`, `169.254.169.254` (metadata cloud), redirect para IP privado. CLI local tem risco baixo, mas sem aviso ético/legal ("só escaneie o que é seu") + sem `CheckRedirect` limitado, é omissão.

**G6. CDN `none` vs `unknown` indefinidos** — `PLAN.md:44,118,100`
Output promete `none/unknown`, `Detect` retorna `unknown`, i18n só tem `cdn.none`. Falta chave `cdn.unknown` e regra: quando é cada um.

**G7. Lista i18n fechada incompleta** — `PLAN.md:100,94`
22 chaves contadas, mas falta: `err.badTimeout` (flag `--timeout` inválida), `err.badLang`, `err.portsFail`, `err.httpRedirect`, `label.server`/`serverExposed`. Lista "fechada" já nasce furada.

## Incoerências com `FIRST.md` e com o próprio plano

**I1. `FIRST.md:12` vs `PLAN.md:162` — conflito frontal.**
`FIRST` exige desde o começo `Swagger/OpenAPI, Diátaxis`. `PLAN` joga ambos para `FORA/backlog`. E `PLAN.md:48` diz `FIRST.md intocado` — não pode ficar intocado se contradiz o plano.

**I2. Propósito contraditório** — `FIRST.md:20` vs `PLAN.md:57-59`
`FIRST`: "Não é app pra terceiros, apenas por mim". `PLAN`: entrega `MIT + CoC + CONTRIBUTING + SECURITY` como se fosse para terceiros. Ou é pessoal (CoC/Security overkill, sem email de contato) ou é público (falta suporte, versions, contato).

**I3. Nome do produto incoerente** — `PLAN.md:14,33,63`
Repo `gosomething` vs binário/pacote `exposcan`. Placeholder vazou para decisão travada. Renomear repo ou justificar em ADR.

**I4. IPv6 ambíguo** — `PLAN.md:44` vs `PLAN.md:162`
Promete `IPs (A/AAAA)` mas põe `IPv6 avançado` em FORA. O que é "avançado"? Sem definição, aceite é inverificável.

**I5. `go.mod` vago** — `PLAN.md:91`
`require golang.org/x/net vX (última compatível)` não é pin. Build não-reprodutível. Travar versão exata.

**I6. Árvore omite testes** — `PLAN.md:68-76` vs `PLAN.md:133`
Árvore lista `_test.go` para `i18n/validate/cdn/exposcan`, mas para `dns/httpfetch/ports` diz só `(+ test com mock)`. `ports/checker_test.go` aparece depois sem estar na árvore. Nada além/nada a menos? Falso.

**I7. CDN teste cobre 4/7** — `PLAN.md:118,131`
Especifica 7 (Cloudflare, CloudFront, Akamai, Fastly, Sucuri, Incapsula, DDoS-Guard), teste só lista 4 + unknown. Sucuri/Incapsula/DDoS-Guard sem cobertura.

**I8. Regex proíbe single-label sem dizer** — `PLAN.md:104`
`(...\....)+$` exige ponto. `localhost` sempre falha. Intencional? Não documentado.

**I9. `ToLower` antes de `ToASCII`** — `PLAN.md:104`
Quebra case-folding IDN. `idna.ToASCII` já faz mapping correto; lower manual com `strings.ToLower` (turco `I`, etc.) é errado.

**I10. Mapeamento erro→i18n ausente** — `PLAN.md:105`
`validate` retorna `ErrEmpty, ErrInvalid`, mas i18n tem `tooLong, labelTooLong, badChars...`. Sem tabela de mapeamento, `main` não sabe traduzir.

**I11. `Detect(flag string)` impuro** — `PLAN.md:99`
Se lê `LANG/LC_ALL` dentro via `os.Getenv`, é intestável e viola a própria regra de mocks. Tem que receber env como parâmetro.

**I12. Exit codes incompletos** — `PLAN.md:95`
`0 ok, 1 rede, 2 uso`. Onde cai `timeout`? E sucesso parcial (DNS ok, HTTP fail)? Sem regra, `--json` + exit code divergem.

**I13. Commit único viola review** — `PLAN.md:169`
`1 commit com módulo+lint+docs+CLI` contradiz `conventional commits + atomicidade`. Para review de PR, tem que ser N commits pequenos.

**I14. Lint fora do loop e do aceite** — `PLAN.md:21,172-178`
Cria `.golangci.yml` com 5 linters, mas test loop é só `gofmt→vet→test` e aceite não cobra `golangci-lint`. Config morta. Também falta versão do `golangci` (v1 vs v2 quebra sintaxe) e `goimports` vs `gofmt -l` duplicados.

**I15. Doc comment sem enforcement** — `PLAN.md:22` vs `PLAN.md:18`
Exige doc em exportado "exigido por linters", mas desliga `revive` — justo o linter que exigiria. `staticcheck/govet` não cobrem isso.

**I16. Badges sem CI + `.gitignore` furado** — `PLAN.md:149,61`
`README com badges mínimos` sem CI = badge quebrado. `.gitignore` ignora `/exposcan` mas não `exposcan.exe` (Windows). E criar `.gitignore` por último no workflow (`PLAN.md:167`) permite commitar binário antes.

**I17. Detalhes de ambiente errados** — `PLAN.md:28,39`
`winget install Go.Go --version...` falta `--id`. `münchen.de` no `cmd.exe` tem problema de encoding não tratado. `exemplo.com` vs `example.com` misturados sem padrão.

**I18. Aceite fraco + `PLAN.md` fora do workflow** — `PLAN.md:175,178`
`ou falham com mensagem amigável se sem internet` = aceite que passa falhando. E `PLAN.md → APPROVED` após ok exige commit extra não previsto no workflow.

## O que fazer antes do `ok`

1. Corrigir B1-B8 (assinaturas, ordem, git init com `main`, schema JSON, validação pós-punycode, portas parametrizáveis).
2. Travar: timeouts por etapa, estratégia HTTP (`HEAD`→`GET`, limite bytes/redirects, UA, TLS), `Close()`, `Deps` tipado, tabela erro→i18n + chaves faltantes, `none` vs `unknown`.
3. Resolver I1-I2: ou atualiza `FIRST.md` ou tira `Swagger/Diátaxis/CoC` do backlog. Definir contato `SECURITY.md` e holder legal do `MIT` (não só `matheuslyam`).
4. Renomear repo ou ADR explicando `gosomething` vs `exposcan`; pinar `x/net`; incluir `golangci` no loop/aceite; corrigir `.gitignore` (`.exe`); tirar badges sem CI.
5. Reescrever §5.9, §6 e §11 com ordem, comandos e critérios verificáveis (sem "passa se falhar sem internet").

Verificado e OK: Go `1.27.2` em `2026-10-02` (`go.dev/VERSION?m=text` retorna `go1.27.2`).
