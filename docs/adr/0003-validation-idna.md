# ADR 0003: Domain validation with `idna.Lookup`, no network

## Status

Accepted.

## Context

CLI input needs IDN support (e.g. `münchen.de` → `xn--mnchen-3ya.de`) without
reinventing punycode, and friendly bilingual errors before any network call.

## Decision

Validate purely: trim, strip one trailing dot, reject empty/single-label
(`localhost` needs a FQDN), convert via `idna.Lookup.ToASCII` (no manual
`ToLower` — UTS46 folding already handles it), then enforce 253/63 limits and
per-label charset on the ASCII form. Single external dep: `x/net v0.61.0`.

## Consequences

`ValidateDomain` returns display + ASCII forms with a typed `ErrCode` mapped
to i18n keys. Discarded: hand-rolled punycode and stdlib-only ASCII rejection
of all IDNs.
