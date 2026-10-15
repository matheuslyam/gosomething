# exposcan (dentro do `gosomething`)

`gosomething` é um laboratório pessoal de Go + redes, construído em público
desde o primeiro dia. `exposcan` é sua primeira ferramenta: um scanner mínimo
de exposição de domínios — não um nmap.

Dado um domínio, ele mostra os IPs resolvidos, CNAME, heurística de CDN,
headers de segurança e se as portas 80/443 estão abertas. Escaneie apenas
domínios seus ou com autorização.

## Início rápido

Requisito: Go 1.27 (`go version go1.27.0`).

```bash
go build -o exposcan ./cmd/exposcan
./exposcan exemplo.com
./exposcan --lang en example.com
./exposcan --json --timeout 10s exemplo.com
./exposcan --secrets exemplo.com
./exposcan --secrets --reveal exemplo.com
```

## Uso

```text
Uso: exposcan [--lang en|pt] [--timeout 5s|10s|15s|30s] [--json] [--secrets] [--reveal|-rv] <dominio>
```

* `--lang en|pt` — idioma (padrão automático: `LANG`/`LC_ALL`, fallback EN).
* `--timeout` — timeout global, um de `5s|10s|15s|30s` (padrão `15s`).
* `--json` — saída para máquinas (`Result` ou `SecretsResult`, ou `ErrorEnvelope` em falha).
* `--secrets` — caça segredos vazados no frontend (HTML + inline + até 10 `.js`, mesma origem primeiro) em vez do scan de exposição.
* `--reveal` (`-rv`) — mostra os valores completos; precisa de `--secrets`. O padrão é mascarado (`AKIA…MPLE`) para não vazar em logs e vídeos.
* Exit codes: `0` concluído (mesmo parcial com avisos, ou `--secrets` limpo), `1` falha de
  rede/timeout, `2` uso ou validação, `3` `--secrets` achou ao menos um possível segredo.

## Como funciona

`validate` (IDN via `idna.Lookup`, sem rede) → DNS (`LookupIPAddr`+CNAME) →
headers HTTP (`https://`, fallback para `http://` só em falha de transporte) →
heurística de CDN (sufixo CNAME + headers) → probes TCP em 80/443 em paralelo.
Veja `docs/architecture.md` e `docs/adr/`.

Privacidade: valores de `Set-Cookie` nunca são guardados — só presença. `--secrets` é mascarado por padrão pelo mesmo motivo; use `--reveal` só em domínios seus, nunca cole valores completos em issues ou vídeos.

## Roteiro

* Releases com `goreleaser`, CI, passo de lint `revive`, docs Diátaxis completas.
* Detecção WAF/ASN, modo verboso com motivos, entrada multi-domínios.

## Licença

MIT — veja [LICENSE](LICENSE).
