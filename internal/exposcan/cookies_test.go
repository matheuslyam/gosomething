package exposcan

import (
	"testing"
)

func TestMaskCookieValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"value masked attrs intact", "session=AbCdEfGh1234; Path=/; Secure; HttpOnly", "session=AbCd…1234; Path=/; Secure; HttpOnly"},
		{"short value stars", "id=abc; Path=/", "id=****; Path=/"},
		{"empty value stars", "id=; Path=/", "id=****; Path=/"},
		{"base64 padding kept split on first eq", "tok=QUJDREVGRw==; Secure", "tok=QUJD…Rw==; Secure"},
		{"no attributes", "session=AbCdEfGh1234", "session=AbCd…1234"},
		{"no equals passthrough", "just-a-flag", "just-a-flag"},
		{"empty passthrough", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := MaskCookieValue(tt.raw); got != tt.want {
				t.Errorf("MaskCookieValue(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestMaskCookiesEmpty(t *testing.T) {
	t.Parallel()

	if got := MaskCookies(nil); len(got) != 0 {
		t.Errorf("MaskCookies(nil) = %v, want empty", got)
	}
}
