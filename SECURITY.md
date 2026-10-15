# Security Policy

This is a personal learning project, built in public. There is no SLA and no
dedicated security team.

## Reporting a vulnerability

Open a GitHub Issue on this repository or email
[matheuslyambusiness@gmail.com](mailto:matheuslyambusiness@gmail.com) with
`[SECURITY]` in the subject. Please include steps to reproduce and the
affected version/commit.

## Scope

`exposcan` only reads public information (DNS, HTTP headers, TCP open/closed
on ports 80/443). `--secrets` additionally reads HTML and JavaScript bodies
(up to 10 `.js`, 2MB each, still GET-only reads). It does not exploit,
brute-force, or bypass access controls.
Please only scan domains you own or are authorized to test. `--reveal`
prints full secret values — use it only on your own domains and never share
that output.
