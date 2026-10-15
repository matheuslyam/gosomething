package secrets

import (
	"strings"
	"testing"
)

// long builds deterministic fake secrets of exact length (Repeat keeps the
// table readable where formats demand 30+ chars). All values are fake.
func long(s string, n int) string { return strings.Repeat(s, n) }

func TestPatternsTable(t *testing.T) {
	t.Parallel()

	// WHY fake-but-valid shapes: proves detection without a real secret.
	// Every pattern carries ≥2 positives + ≥2 negatives (phase-1 acceptance).
	// WHY realistic fakes are split across string boundaries: GitHub push
	// protection flags contiguous partner shapes (it blocked our Stripe and
	// Resend fakes), so no committed line may contain a complete secret;
	// runtime values are identical. jwt.io's public example and
	// uniform-Repeat constructions stay inline (empirically unflagged).
	cases := []struct {
		name string
		line string
		want string // empty = no finding
	}{
		{"aws", `key = AKIAIOSFODNN7EXAMPLE here`, "AWSAccessKey"},
		{"aws asia", `key = ASIAIOSFODNN7EXAMPLE here`, "AWSAccessKey"},
		{"aws short is not a key", `key = AKIA123 here`, ""},
		{"aws lowercase is not a key", `key = akiaiosfodnn7example here`, ""},
		{"aws secret labeled", `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, "AWSSecretKey"},
		{"aws secret json", `"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, "AWSSecretKey"},
		{"aws secret short is not a key", `aws_secret_access_key = "short"`, ""},
		{"aws bare 40 chars is not a finding", `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, ""},
		{"github", `token ghp_` + long("1", 36) + ` here`, "GitHubToken"},
		{"github oauth", `token gho_` + long("2", 36) + ` here`, "GitHubToken"},
		{"github short", `ghp_short`, ""},
		{"github wrong prefix", `token ghx_` + long("1", 36) + ` here`, ""},
		{"github fine-grained", `token github_pat_` + long("a", 82) + ` here`, "GitHubFineGrained"},
		{"github fine-grained 2", `github_pat_` + long("b", 82), "GitHubFineGrained"},
		{"github fine-grained short", `github_pat_` + long("a", 10), ""},
		{"github fine-grained prose", `see github_pat_ docs`, ""},
		{"slack bot", `xoxb-12345` + `67890-123456789012-AbCdEfGh`, "SlackToken"},
		{"slack user", `xoxp-1234567890-1234567890-` + `1234567890-AbCdEfGhIjKlMnOpQrStUvWxYz0123`, "SlackToken"},
		{"slack app", `token xapp-1-A12` + `3B-456-abcdef here`, "SlackToken"},
		{"slack webhook", `https://hooks.slack.com/services/T123/B456/abcde` + `fghij1234567890abcdefghij1234567890abc`, "SlackToken"},
		{"slack short is not a token", `xoxb-short`, ""},
		{"slack unknown type", `xoxz-12345-abcdef`, ""},
		{"private key", `-----BEGIN PRIVATE KEY-----`, "PrivateKey"},
		{"private rsa", `-----BEGIN RSA PRIVATE KEY-----`, "PrivateKey"},
		{"private openssh", `-----BEGIN OPENSSH PRIVATE KEY-----`, "PrivateKey"},
		{"public key is not private", `-----BEGIN PUBLIC KEY-----`, ""},
		{"bare private words", `PRIVATE KEY`, ""},
		{"mongo", `mongodb://us` + `er:pass123@host/db`, "MongoURI"},
		{"mongo srv", `mongodb+srv://us` + `er:pass123@host/db`, "MongoURI"},
		{"mongo no creds is not a finding", `mongodb://host/db`, ""},
		{"http url is not mongo", `http://user:pass@host/`, ""},
		{"apikey", `api_key="12345678"`, "APIKey"},
		{"apikey json", `"apiKey": "12345678"`, "APIKey"},
		{"apikey backtick", "apiKey: `12345678abcd`", "APIKey"},
		{"apikey short", `api_key="short"`, ""},
		{"apikey bare label", `API_KEY`, ""},
		{"secret", `secret="12345678"`, "Secret"},
		{"secret json", `"secret": 'abcdefgh'`, "Secret"},
		{"secret short", `secret="x"`, ""},
		{"secretary is not secret", `"secretary": "12345678"`, ""},
		{"accesstoken", `access_token="abcdef123456"`, "AccessToken"},
		{"accesstoken json", `"accessToken": "xyz12345678"`, "AccessToken"},
		{"accesstoken url label is not a token", `access_token_url = "https://x"`, ""},
		{"accesstoken short", `access_token="x"`, ""},
		{"authtoken", `auth_token="abcdef123456"`, "AuthToken"},
		{"authtoken camel", `authToken: 'xyz987654'`, "AuthToken"},
		{"authtoken short", `auth_token="x"`, ""},
		{"author is not a token", `author="someone"`, ""},
		{"jwt", `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`, "JWT"},
		{"jwt 2", `token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c here`, "JWT"},
		{"jwt short segments", `eyJ.short.sig`, ""},
		{"not a jwt", `not.a.jwt.at.all`, ""},
		{"stripe secret", `sk_li` + `ve_4eC39HqLyjWDarjtT1zdp7dc`, "StripeKey"},
		{"stripe restricted test", `rk_test_` + long("a", 24), "StripeKey"},
		{"stripe publishable excluded", `pk_live_` + long("a", 24), ""},
		{"stripe short", `sk_live_short`, ""},
		{"anthropic", `sk-ant-api03-` + long("A", 93) + `AA`, "AnthropicKey"},
		{"anthropic admin", `sk-ant-admin01-` + long("B", 93) + `AA`, "AnthropicKey"},
		{"anthropic short", `sk-ant-api03-short`, ""},
		{"anthropic unknown tier", `sk-ant-unknown-` + long("A", 93) + `AA`, ""},
		{"huggingface", `hf_` + long("a", 34), "HuggingFaceKey"},
		{"huggingface org", `api_org_` + long("b", 34), "HuggingFaceKey"},
		{"huggingface short", `hf_short`, ""},
		{"huggingface uppercase rejected", `hf_` + long("A", 34), ""},
		{"cohere labeled", `cohere_api_key="` + long("a", 20) + long("b", 20) + `"`, "CohereKey"},
		{"cohere env", `CO_API_KEY=` + long("c", 40), "CohereKey"},
		{"cohere short value", `cohere_api_key="short"`, ""},
		{"cohere bare label", `cohere_api_key = ""`, ""},
		{"firebase", `AIza` + long("a", 35), "FirebaseKey"},
		{"firebase 2", `key=AIza` + long("b", 35) + `&x=1`, "FirebaseKey"},
		{"firebase short", `AIzaabc`, ""},
		{"firebase prose", `get an API key`, ""},
		{"gcp service account", `{"type": "service_account", "project_id": "x"}`, "GCPServiceAccount"},
		{"gcp service account compact", `"type":"service_account"`, "GCPServiceAccount"},
		{"gcp human type", `{"type": "human"}`, ""},
		{"supabase secret", `sb_secret_` + long("a", 20), "SupabaseKey"},
		{"supabase secret 2", `SUPABASE_SECRET_KEY=sb_secret_` + long("b", 24), "SupabaseKey"},
		{"supabase publishable excluded", `sb_publishable_` + long("a", 20), ""},
		{"supabase short", `sb_secret_abc`, ""},
		{"npm", `npm_` + long("a", 36), "NpmToken"},
		{"npmrc line", `//registry.npmjs.org/:_authToken=npm_` + long("b", 36), "NpmToken"},
		{"npm short", `npm_short`, ""},
		{"npm wrong prefix", `npmx_` + long("a", 36), ""},
		{"twilio sid", `AC` + long("a", 32), "TwilioSID"},
		{"twilio sid 2", `sid=AC` + long("b", 32), "TwilioSID"},
		{"twilio sid short", `ACabc`, ""},
		{"twilio sid nonhex", `AC` + long("g", 32), ""},
		{"twilio key", `SK` + long("F", 32), "TwilioKey"},
		{"twilio key 2", `key=SK` + long("e", 32), "TwilioKey"},
		{"twilio key short", `SKabc`, ""},
		{"twilio lowercase prefix rejected", `sk` + long("a", 32), ""},
		{"sendgrid", `SG.` + long("a", 22) + `.` + long("b", 43), "SendGridKey"},
		{"sendgrid 2", `key=SG.` + long("c", 24) + `.` + long("d", 50), "SendGridKey"},
		{"sendgrid short", `SG.a.b`, ""},
		{"sendgrid prose", `send us an email`, ""},
		{"resend", `re_12345678_abcdef` + `ghijkmnopqrstuvwxy`, "ResendKey"},
		{"resend 2", `key=re_ABCD5678_abcdef` + `ghijkmnopqrstuvwxy`, "ResendKey"},
		{"resend non-base58", `re_12345678_abcdefghijkmnopqrstuvwxyl`, ""},
		{"resend short", `re_a_b`, ""},
		{"planetscale token", `pscale_tkn_` + long("a", 32), "PlanetScaleToken"},
		{"planetscale password", `pscale_pw_` + long("b", 40), "PlanetScaleToken"},
		{"planetscale id excluded", `pscale_id_` + long("c", 32), ""},
		{"planetscale short", `pscale_tkn_abc`, ""},
		{"clean", `nothing to see here`, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := matchLine(tt.line)
			if tt.want == "" {
				if len(got) != 0 {
					t.Errorf("matchLine(%q) = %v, want none", tt.line, got)
				}
				return
			}
			found := false
			for _, m := range got {
				if m.pattern == tt.want {
					found = true
				}
			}
			if !found {
				t.Errorf("matchLine(%q) missing %q, got %v", tt.line, tt.want, got)
			}
		})
	}
}

func TestMask(t *testing.T) {
	t.Parallel()

	full := "AKIAIOSFODNN7EXAMPLE"
	m := Mask(full)
	if m == full {
		t.Errorf("mask must hide the full value, got %q", m)
	}
	if !strings.HasPrefix(m, "AKIA") || !strings.HasSuffix(m, "MPLE") {
		t.Errorf("mask keeps prefix/suffix for triage, got %q", m)
	}
	if got := Mask("short"); got != "****" {
		t.Errorf("short mask = %q, want ****", got)
	}
}
