# ADR 0009: --secrets coverage expansion (29 patterns, verified)

## Status

Accepted.

## Context

The 7 initial patterns came 1:1 from the feature handoff without asking for
the owner's real key inventory (process failure, admitted in-session). The
owner then named 5 families: LLMs, payments/fintechs, cloud, dev/infra/CI,
comms — plus two architecture questions (entropy double-verification for
prefixless keys, git history scan).

## Decision

Phase 1 (this ADR): fix the JSON/backtick gap in `APIKey`/`Secret`
(`"apiKey": "v"` was invisible — the dominant frontend shape) and ship
named patterns for every requested family whose format verifies against a
source below. Every length floor cites either an exact verified shape or a
documented heuristic; nothing ships from memory alone.

Verification table (all fetched 2026-10-15):

| Pattern | Source |
|---|---|
| AWSAccessKey (`A3T/KIA/SIA/BIA/CCA` + base32×16) | gitleaks `aws-access-token` rule + AWS IAM `reference_identifiers` (prefix table) |
| AWSSecretKey (labeled 40-char) | GitHub partner table (`aws_secret_access_key`, validity-checked); 40-char constant |
| GitHubToken (`gh[pousr]_`+36), GitHubFineGrained (`github_pat_`+82) | gitleaks `github-pat`, `github-oauth`, `github-app-token`, `github-refresh-token`, `github-fine-grained-pat` |
| SlackToken union (bot/user/app/legacy/webhook/xoxs) | gitleaks `slack-*` rules + Slack token-types docs (`xoxb-`, `xoxp-`, `xwfp-`, `xapp-`); `xoxs` carried from handoff |
| PrivateKey (`RSA/EC/OPENSSH/DSA/PGP/ENCRYPTED`) | GitHub generic rows (rsa/ec/openssh/pgp/private-key) |
| JWT (eyJ-only, 17/17/10 floors) | trufflehog `jwt` keyPat (eyJ-first two segments) |
| StripeKey (`sk/rk` test/live/prod + `sk_org_`) | gitleaks `stripe-access-token` + Stripe keys docs (prefixes; `pk_` public by design) |
| AnthropicKey (`sk-ant-admin01/api03-…93AA`) | trufflehog `anthropic` keyPat + gitleaks `anthropic-api-key` (cross-confirmed) |
| HuggingFaceKey (`hf_`/`api_org_` + 34lc) | gitleaks `huggingface-access-token`; prefix corroborated by HF security-tokens docs |
| CohereKey (label-context, 40 alnum) | gitleaks `cohere-api-token` (no published prefix exists) |
| FirebaseKey (`AIza`+35) | gitleaks `gcp-api-key` |
| GCPServiceAccount (`"type": "service_account"`) | GitHub partner row `google_cloud_service_account_credentials` |
| SupabaseKey (`sb_secret_` only) | Supabase api-keys docs (`sb_secret_` secret / `sb_publishable_` public); legacy service_role JWTs ride on JWT |
| NpmToken (`npm_`+36) | gitleaks `npm-access-token`; legacy prefixless gone since 11/2025 (npm docs) |
| TwilioSID/Key (`AC`/`SK` + 32hex) | trufflehog `twilio` (SID) + gitleaks `twilio-api-key` (SK) |
| SendGridKey (`SG.22.43`) | trufflehog `sendgrid` keyPat |
| ResendKey (`re_8_24` base58) | trufflehog `resend` keyPat |
| PlanetScaleToken (`pscale_tkn_/oauth_/pw_`) | gitleaks `planetscale-*`; `PLANETSCALE_SERVICE_TOKEN=` syntax per PlanetScale docs |
| APIKey/Secret/AccessToken/AuthToken generics | own generalization (gitleaks `generic-api-key` corroborates label-context + backtick approach) |

Deliberate exclusions (WHY each): `pk_*`/`sb_publishable_*` (public by
design — flagging them is noise); bare 32-hex (md5 factory; trufflehog only
reports it paired with a SID, which a line matcher cannot do); `APP_USR-`
(Mercado Pago docs fetched 2026-10-15 publish no format; labeled assignments
still caught by AccessToken); Cohere/`npm_` dedicated prefixes (none exist);
unquoted dotenv values (prose FP; known gap); `xoxe` CLI-machine tokens
(never in bundles).

## Consequences

`Finding.Pattern` gains values; `SecretsResult` schema unchanged; no i18n
changes (pattern names are identifiers). Tests: per-pattern ≥2
positive/negative + bundle fixture (`TestScanSecretsBundle`).

Phase 2 (deferred): entropy double-verification for prefixless candidates
(AWS secret without label, bare base64≥32) — Shannon gate with a calibrated
threshold, confirming only, never primary. WHY deferred: uncalibrated
entropy is a false-positive factory that would pollute exit 3.

Phase 3 (own scope + QA): git history scan reusing `matchLine` over
`git log --all -p`, bounded stream, `Finding.File = <commit>:<file>`,
`--history` requiring `--secrets` (mirrors `err.badReveal` → 2).

Discarded: shipping unverified formats from memory (WHY: wrong lengths
either miss real keys or spam findings — both worse than a documented gap);
one loose `xox.*` union (WHY: matches docs prose).
