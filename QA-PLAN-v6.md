# QA — `PLAN.md` v6 — VEREDITO: **REPROVADO (por 1 item funcional)**

v6 fecha C1-C2/G1-G4/M1-M4 da QA-v5. Conferido: `ErrHelp→0`, `formatters.goimports`, `peekLang`, `IPs fatal/CNAME tolera`, `HTTPError` preservado, `SingleLabel` antes do `idna`, `Canceled≠timeout`, sufixos Akamai, `version` logada. Árvore confere (`QA-PLAN-v5.md` existe).

Resta 1 buraco que gera divergência na implementação:

**NArg sem regra — `PLAN.md:148-151` vs `PLAN.md:92`**
Contrato: `1 FQDN`. `run` faz `ValidateDomain(arg)`, mas nunca trava `fs.NArg()`. Consequências:
- `./exposcan` (0 args): funciona por acidente (`Arg(0)==""` → `ErrEmpty`), mas não está escrito.
- `./exposcan a.com b.com` (2+): silenciosamente ignora o 2º — viola o contrato.
- `./exposcan example.com --lang pt` (flag após posicional): `peekLang` acha `pt`, mas o `FlagSet` trata `--lang pt` como posicionais (`NArg=3`). Sem regra, um implementador perdoa (usa 1º + lang do peek), outro erra — e o WHY de `PLAN.md:148` ("ordem fixa") exige erro.

Fix v7 (1 parágrafo em §5.2):
`após Parse: if fs.NArg()!=1 → ErrorEnvelope(err.noDomain/usage) → return 2; arg:=fs.Arg(0)`. `peekLang` varre tudo só para idioma da mensagem/Usage, não para aceitar flag fora de ordem.

Higiene (não bloqueia, corrigir junto): `PLAN.md:17` (`nesta v5`), `PLAN.md:41` (`esta v5`), `PLAN.md:162` (`Chaves §v4`) ainda apontam v4/v5 — trocar por v6.

Com o `NArg` travado é `go`.
