# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

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
