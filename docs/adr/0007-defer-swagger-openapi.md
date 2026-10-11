# ADR 0007: Defer Swagger/OpenAPI until an HTTP API exists

## Status

Accepted.

## Context

`FIRST.md` lists Swagger/OpenAPI as professional-doc direction. The v1
product is a CLI with no HTTP API, so generated API docs would be dead docs.

## Decision

Defer Swagger/OpenAPI until `exposcan` (or a sibling) exposes an HTTP API.
`FIRST.md` stays untouched as historical intent; this ADR supersedes it for
v1. Diátaxis grows incrementally (`architecture.md` + ADRs now).

## Consequences

No OpenAPI artifacts in v1. Revisit when an HTTP service is planned.
