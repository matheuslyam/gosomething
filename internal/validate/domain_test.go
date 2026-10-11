package validate

import (
	"strings"
	"testing"
)

func TestValidateDomain(t *testing.T) {
	t.Parallel()

	longLabel := strings.Repeat("a", 64) + ".com"
	tooLong := strings.Repeat("a.", 130) + "com" // >253 ASCII chars

	tests := []struct {
		name     string
		input    string
		wantOrig string
		wantCode ErrCode
	}{
		{"simple", "example.com", "example.com", ErrOK},
		{"subdomain", "sub.example.com.br", "sub.example.com.br", ErrOK},
		{"trailing dot stripped", "example.com.", "example.com", ErrOK},
		{"surrounding spaces", "  example.com  ", "example.com", ErrOK},
		{"idn", "münchen.de", "münchen.de", ErrOK},
		{"empty", "", "", ErrEmpty},
		{"spaces only", "   ", "", ErrEmpty},
		{"single label", "localhost", "localhost", ErrSingleLabel},
		{"double dot", "a..b.com", "a..b.com", ErrBadChars},
		{"double trailing dot", "example.com..", "example.com.", ErrBadChars},
		{"leading hyphen", "-a.com", "-a.com", ErrBadChars},
		{"trailing hyphen label", "a-.com", "a-.com", ErrBadChars},
		{"scheme not a domain", "http://a.com", "http://a.com", ErrBadChars},
		{"underscore", "a_b.com", "a_b.com", ErrBadChars},
		{"label too long", longLabel, longLabel, ErrLabelTooLong},
		{"too long", tooLong, strings.TrimSuffix(strings.TrimSpace(tooLong), "."), ErrTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			orig, ascii, code := ValidateDomain(tt.input)
			if orig != tt.wantOrig {
				t.Errorf("original = %q, want %q", orig, tt.wantOrig)
			}
			if code != tt.wantCode {
				t.Errorf("code = %q, want %q", code, tt.wantCode)
			}
			if code == ErrOK && ascii == "" {
				t.Error("valid domain must return non-empty ascii")
			}
			if code != ErrOK && tt.name == "idn" {
				t.Error("unreachable")
			}
		})
	}
}

func TestValidateDomainIDNASCII(t *testing.T) {
	t.Parallel()

	orig, ascii, code := ValidateDomain("münchen.de")
	if code != ErrOK {
		t.Fatalf("code = %q, want ok", code)
	}
	if orig != "münchen.de" {
		t.Errorf("original = %q, want display form preserved", orig)
	}
	if ascii != "xn--mnchen-3ya.de" {
		t.Errorf("ascii = %q, want punycode", ascii)
	}
}

// The ErrCode→i18n table must cover every error code so main can always
// translate a validation failure into a bilingual message.
func TestErrCodeToI18nComplete(t *testing.T) {
	t.Parallel()

	for _, code := range []ErrCode{ErrEmpty, ErrTooLong, ErrLabelTooLong, ErrBadChars, ErrSingleLabel, ErrInvalid} {
		if ErrCodeToI18n[code] == "" {
			t.Errorf("ErrCode %q has no i18n key", code)
		}
	}
}
