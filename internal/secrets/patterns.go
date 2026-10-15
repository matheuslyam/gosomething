// Package secrets hunts leaked frontend secrets in HTML and JavaScript.
package secrets

import (
	"regexp"
)

// patternDef pairs a stable pattern name with its compiled matcher.
// WHY stable names (not the regexp) in output: the report stays greppable
// (arquivo:linha:padrão) without depending on regexp syntax drift.
type patternDef struct {
	name string
	re   *regexp.Regexp
}

// Verification table (AGENTS.md §3: never the model cutoff).
// Prefixes verified 2026-10-15 against:
//
//	[GH]  GitHub secret-scanning-patterns docs (token-type existence +
//	      multi-version warning that justifies tolerant length floors)
//	[TH]  trufflehog pkg/detectors (jwt, sendgrid, twilio, stripe,
//	      anthropic, resend) via raw.githubusercontent
//	[GL]  gitleaks config/gitleaks.toml (aws, anthropic, cohere, gcp-api-key,
//	      github×6, huggingface, npm, planetscale×3, slack×7, stripe,
//	      twilio-api-key)
//	[DOC] provider docs: Stripe keys, Supabase api-keys (sb_secret_ secret /
//	      sb_publishable_ public), HF security-tokens (hf_ prefix), npm
//	      access-tokens (granular-only since 11/2025, legacy removed),
//	      PlanetScale service-tokens (PLANETSCALE_SERVICE_TOKEN= syntax),
//	      Slack token-types, AWS IAM reference_identifiers (ABIA/ACCA/AKIA/ASIA)
//
// Deliberate exclusions (see ADR-0009): Stripe pk_ and Supabase
// sb_publishable_ (public by design [DOC]); bare 32-hex (md5 factory —
// trufflehog only reports it paired with a SID, which a line matcher can't
// do); Cohere/APP_USR-/SK-less prefixes (unpublished format); npm legacy
// (removed); unquoted dotenv values (known gap, future work).
var patterns = []patternDef{
	// AWSAccessKey also flags ABIA/ACCA/A3T credential IDs under one name.
	// WHY one name: same triage action (check IAM); split names would only
	// help auditors, not the bancada video workflow. [GL][DOC-AWS]
	{name: "AWSAccessKey", re: regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b`)},
	// AWSSecretKey only fires next to a label: a bare 40-char string is
	// indistinguishable from base64 noise, so prefixless matching waits
	// for the phase-2 entropy verifier (ADR-0009).
	{name: "AWSSecretKey", re: regexp.MustCompile(`(?i)(?:aws_secret|secret_access_key)["']?\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`)},
	// GitHub classic family, all 40 chars total. [GL]
	{name: "GitHubToken", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`)},
	// GitHub fine-grained PAT, exact 93-char shape. [GL]
	{name: "GitHubFineGrained", re: regexp.MustCompile(`\bgithub_pat_\w{82}\b`)},
	// SlackToken union: strict bot/user/app shapes, legacy workspace/RTM
	// shapes, service tokens (handoff carry-over), webhook URLs. [GL][DOC]
	// WHY union, not one loose xox regexp: each arm is a verified shape;
	// a loose `xox.-` would match docs prose. xoxe CLI-machine tokens
	// skipped (never in bundles; entropy backstop).
	{name: "SlackToken", re: regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*|xoxp(?:-[0-9]{10,13}){3}-[A-Za-z0-9-]{28,34}|xapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[a-z0-9]+|xox[os]-[0-9]+-[0-9]+-[0-9]+-[a-fA-F0-9]+|xox[ar]-(?:[0-9]-)?[A-Za-z0-9]{8,48}|xoxs-[A-Za-z0-9-]+|hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}`)},
	// PrivateKey header line alone is the signal (a header proves an
	// embedded key; the line matcher never sees the multiline body).
	// Types corroborated by [GH] generic rows (rsa/ec/openssh/pgp).
	{name: "PrivateKey", re: regexp.MustCompile(`BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY`)},
	// MongoURI unchanged (handoff); class corroborated by [GH] high-precision
	// mongodb_atlas_db_uri_with_credentials row.
	{name: "MongoURI", re: regexp.MustCompile(`mongodb(\+srv)?://[^ \t\r\n'"]+:[^ \t\r\n'"]+@`)},
	// APIKey/Secret accept quoted key names (JSON `"apiKey": "v"`) and
	// quote/backtick values. Unquoted dotenv values stay out by design
	// (prose FP); bare-prefix providers below need no quotes at all.
	{name: "APIKey", re: regexp.MustCompile("(?i)[\"']?api[_-]?key[\"']?\\s*[:=]\\s*[\"'`][^\"'`]{8,}")},
	{name: "Secret", re: regexp.MustCompile("(?i)[\"']?secret[\"']?\\s*[:=]\\s*[\"'`][^\"'`]{8,}")},
	// AccessToken/AuthToken generics catch labeled credentials the two
	// above miss (oauth, access_token=, auth_token=, MP-labeled tokens).
	// Same quoted-value discipline as APIKey/Secret.
	{name: "AccessToken", re: regexp.MustCompile("(?i)access[ _-]?token[\"']?\\s*[:=]\\s*[\"'`][^\"'`]{8,}")},
	{name: "AuthToken", re: regexp.MustCompile("(?i)auth_?token[\"']?\\s*[:=]\\s*[\"'`][^\"'`]{8,}")},
	// JWT eyJ-only: Supabase legacy anon/service_role plus the vast
	// majority of frontend JWTs start eyJ (`{"`). Floors per [TH].
	{name: "JWT", re: regexp.MustCompile(`\bey[A-Za-z0-9_-]{17,}\.ey[A-Za-z0-9_-]{17,}\.[A-Za-z0-9_-]{10,}={0,2}\b`)},
	// StripeKey covers test+live+prod (broader than [TH] live-only).
	// WHY broader: a sk_test_ in a bundle proves secret-handling failure
	// and the masked report makes the extra signal cheap. pk_ excluded:
	// publishable by design [DOC].
	{name: "StripeKey", re: regexp.MustCompile(`\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b`)},
	// Stripe org keys share the family floor; prefix per [DOC].
	{name: "StripeKey", re: regexp.MustCompile(`\bsk_org_[A-Za-z0-9]{10,99}\b`)},
	// AnthropicKey exact per [TH] (also in [GL]); ends in AA.
	{name: "AnthropicKey", re: regexp.MustCompile(`\bsk-ant-(?:admin01|api03)-[A-Za-z0-9_-]{93}AA\b`)},
	// HuggingFaceKey user + org prefixes; 34-letter bodies per [GL].
	{name: "HuggingFaceKey", re: regexp.MustCompile(`\b(?:hf_|api_org_)[a-z]{34}\b`)},
	// CohereKey is label-context (Cohere publishes no key prefix; [GL]
	// matches 40 alnum next to a cohere/CO_API_KEY label). Floor exact.
	{name: "CohereKey", re: regexp.MustCompile(`(?i)(?:cohere|co_api_key)[^:=]{0,40}[:=]\s*['"]?[a-zA-Z0-9]{40}['"]?`)},
	// FirebaseKey exact per [GL] gcp-api-key rule.
	{name: "FirebaseKey", re: regexp.MustCompile(`\bAIza[\w-]{35}\b`)},
	// GCPServiceAccount fires on the SA marker line; the `"type":
	// "service_account"` literal is the file's fingerprint ([GH] scans
	// google_cloud_service_account_credentials as partner type).
	{name: "GCPServiceAccount", re: regexp.MustCompile(`"type"\s*:\s*"service_account"`)},
	// SupabaseKey matches sb_secret_ only; sb_publishable_ is public by
	// design [DOC]. Legacy service_role JWTs ride on JWT (dedicated test).
	// Floor 20 is heuristic (docs truncate examples); documented here.
	{name: "SupabaseKey", re: regexp.MustCompile(`\bsb_secret_[A-Za-z0-9_-]{20,}\b`)},
	// NpmToken exact per [GL]; legacy prefixless tokens gone since 11/2025
	// [DOC], so no _authToken fallback is kept.
	{name: "NpmToken", re: regexp.MustCompile(`(?i)\bnpm_[a-z0-9]{36}\b`)},
	// TwilioSID exact per [TH]; TwilioKey SK prefix per [GL].
	{name: "TwilioSID", re: regexp.MustCompile(`\bAC[0-9a-f]{32}\b`)},
	{name: "TwilioKey", re: regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)},
	// SendGridKey exact per [TH].
	{name: "SendGridKey", re: regexp.MustCompile(`\bSG\.[\w\-]{20,24}\.[\w\-]{39,50}\b`)},
	// ResendKey exact per [TH] (base58, no 0/O/I/l).
	{name: "ResendKey", re: regexp.MustCompile(`\bre_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}\b`)},
	// PlanetScaleToken prefixed trio per [GL]; branch passwords are
	// prefixless and wait for entropy (ADR-0009). TOKEN_IDs are IDs, not
	// secrets, and are excluded.
	{name: "PlanetScaleToken", re: regexp.MustCompile(`\bpscale_(?:tkn_|oauth_|pw_)[\w=.-]{32,64}\b`)},
}

// match is one regexp hit before masking.
type match struct {
	pattern string
	value   string
}

// matchLine returns every pattern hit in a single line.
func matchLine(line string) []match {
	var out []match
	for _, p := range patterns {
		for _, v := range p.re.FindAllString(line, -1) {
			out = append(out, match{pattern: p.name, value: v})
		}
	}
	return out
}

// Mask hides the middle of a secret for safe-by-default output.
// WHY first4+…+last4: proves which key leaked (prefix identifies the
// account) without printing the full value into terminal/CI/video logs.
// Short matches (<8) reveal nothing useful, so they become "****".
func Mask(v string) string {
	if len(v) < 8 {
		return "****"
	}
	return v[:4] + "…" + v[len(v)-4:]
}
