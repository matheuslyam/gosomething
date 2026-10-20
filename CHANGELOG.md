# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

* Docs verification via `ctx7` CLI (`find-docs` skill, `library` → `docs`)
  replacing the unused remote MCP entry: every signature/version claim now
  cites `primitive + source + date` (AGENTS.md §3, GO-01); `npx ctx7*`
  allowed unattended in opencode permissions.
* QA harness (ADR-0012, `docs/qa-gate/05-harness.md`): executable gate
  (`scripts/qa-gate.ps1`) stamping the staged tree, `pre-commit`/`commit-msg`
  hooks (installed via `scripts/install-hooks.ps1`), single commit path
  (`scripts/qa-commit.ps1`), CI backstop (`.github/workflows/qa.yml`, Go
  1.27.0 exact), opencode permissions denying direct `git commit`. Verdict
  table before commit is now enforced, not remembered.
* `exposcan` CLI: single-domain exposure scan (resolved IPs, CNAME, CDN
  heuristic, security headers, ports 80/443) with bilingual EN-US/PT-BR
  output, `--json`, `--lang`, `--timeout` (default 15s).
* Table-driven unit tests with DNS/HTTP/dial mocks from day one.
* Base docs: `AGENTS.md`, 7 ADRs, `docs/architecture.md` with Mermaid diagram,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`.
* Self-invoking QA gate: thin `.opencode/skills/qa-gate/SKILL.md` plus
  normative `docs/qa-gate/01-universal.md`, `02-adapter-go.md`,
  `03-verdict.md`, `04-loop.md` (max 5 recall rounds, verdict ephemeral in
  commit log); temporary `QA-PLAN*.md` removed.
* `CONTRIBUTING.md` splits agent workflow from product responsible-use
  disclaimer; `AGENTS.md` states the disclaimer is never an agent refusal rule.
* `exposcan --secrets`: separate frontend secret hunt (HTML + inline + up to
  10 `.js` same-origin-first, 2MB cap, masked by default with `--reveal`/`-rv`
  opt-in, exit `3` on findings, `SecretsResult` JSON envelope).
* `exposcan --secrets` coverage: 24 named patterns (AWS incl. ASIA/session
  IDs, GitHub classic + fine-grained, Slack union, JWT, Stripe live/test,
  Anthropic exact, HuggingFace, Cohere-context, Firebase, GCP service
  account, Supabase secret-only, npm, Twilio SID+key, SendGrid, Resend,
  PlanetScale, JSON/backtick-tolerant generics), each format verified
  against provider docs or scanner rulesets (see ADR-0009); entropy and git
  history deferred to phases 2/3.
* `exposcan` WAF heuristic (ADR-0011): separate `waf` field (`Result.waf`,
  `waf:` human line, `waf` JSON key, always `"unknown"` when no edge signal)
  from passive CNAME-suffix + header-presence signals (Cloudflare, Sucuri,
  Incapsula, DDoS-Guard); no `Set-Cookie` values read.
* `exposcan --secrets` entropy double verification (phase 2): prefixless
  collectors (AWS-40, base64≥32, unquoted dotenv, hex-32+) confirmed by
  calibrated per-rule Shannon thresholds (single `HighEntropy` finding,
  named patterns win overlaps, masking unchanged). Calibration proved bare
  matching impossible at zero FP, so collectors require weak context (see
  ADR-0010 for measured values and known residuals).
