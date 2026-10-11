# ADR 0005: Bilingual map without dependencies, EN-US default

## Status

Accepted.

## Context

CLI must speak EN-US and PT-BR natively from day one, without pulling a full
i18n framework for ~30 keys.

## Decision

`internal/i18n` map with `Detect(flag, getEnv)` (`--lang` > `LC_ALL` >
`LANG` > EN) and `T(lang, key, args...)` falling back to EN, then
`[missing:key]`. `TestAllKeysHaveBothLangs` fails the build on a missing
translation.

## Consequences

Zero new dependencies. Discarded: `x/text`, `go-i18n`, gettext — revisit past
~100 keys or complex plurals.
