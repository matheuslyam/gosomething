# QA — `PLAN.md` v7 — VEREDITO: **REPROVADO (micro, 2 itens)**

NArg fechado: `PLAN.md:150` trava `NArg!=1 → 2`, peek só idioma, `TestRun_NArg` com 3 casos, §12 cobra. Todo o resto v6 mantido.

Restam 2 micro-inconsistências que quebram a própria regra do plano:

**1. Árvore omite arquivo existente** — `PLAN.md:98` vs disco
Árvore lista `... / QA-PLAN-v5.md (intocados)`. Existe `QA-PLAN-v6.md` no disco (e o header `PLAN.md:3` diz que responde a ele). Ou entra na árvore ou o `git add` deixa evidência de fora. Trocar por `QA-PLAN*.md (todos, intocados)` ou listar v6.

**2. Envelope do NArg ambíguo** — `PLAN.md:150`
`ErrorEnvelope(err.noDomain/usage)` — qual chave? `err.noDomain` ou `usage`? E `Domain` com 0 args (`""`?) vs 2+ args (`Arg(0)`?). Travar: `NArg!=1 → err.noDomain; Domain = Arg(0) se existir, senão ""`.

Com essas 2 linhas é `go`.
