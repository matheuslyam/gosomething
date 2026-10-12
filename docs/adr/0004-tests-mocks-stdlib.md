# ADR 0004: Table-driven tests with network interfaces, stdlib only

## Status

Accepted.

## Context

Learning goal: see table-driven tests and mocks in practice. Network code
must stay deterministic offline.

## Decision

`testing` only (no testify). `Resolver`/`Fetcher`/`Dialer` interfaces with
stubs; real network only against `localhost`/dynamic ports/`httptest`.
`main` is tested via `run(args, getenv, stdout) int`, never via `os.Exit`.

## Consequences

Every network collaborator is injectable; `Scan` never touches the network in
unit tests. Discarded: live-network tests and an untestable `main()`.
