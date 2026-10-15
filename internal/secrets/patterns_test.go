package secrets

import (
	"strings"
	"testing"
)

func TestPatternsTable(t *testing.T) {
	t.Parallel()

	// WHY fake-but-valid shapes: proves detection without a real secret.
	cases := []struct {
		name string
		line string
		want string // empty = no finding
	}{
		{"aws", "key = AKIAIOSFODNN7EXAMPLE here", "AWSAccessKey"},
		{"aws short is not a key", "key = AKIA123 here", ""},
		{"github", "token ghp_123456789012345678901234567890123456 here", "GitHubToken"},
		{"github short", "ghp_short", ""},
		{"slack bot", "xoxb-12345-abcdef here", "SlackToken"},
		{"private key", "-----BEGIN PRIVATE KEY-----", "PrivateKey"},
		{"mongo", "mongodb://user:pass123@host/db", "MongoURI"},
		{"mongo srv", "mongodb+srv://user:pass123@host/db", "MongoURI"},
		{"apikey", `api_key="12345678"`, "APIKey"},
		{"apikey short", `api_key="short"`, ""},
		{"secret", `secret="12345678"`, "Secret"},
		{"clean", "nothing to see here", ""},
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
