package i18n

import (
	"strings"
	"testing"
)

// Every key present in either language must exist (non-empty) in both.
// WHY: the plan closes the i18n list per build; a key added in one language
// only would render "[missing:key]" at runtime for the other.
func TestAllKeysHaveBothLangs(t *testing.T) {
	t.Parallel()

	union := map[string]bool{}
	for _, m := range messages {
		for k := range m {
			union[k] = true
		}
	}
	if len(union) == 0 {
		t.Fatal("no i18n keys defined")
	}
	for _, lang := range []Lang{EN, PT} {
		for k := range union {
			if messages[lang][k] == "" {
				t.Errorf("lang %s is missing key %q", lang, k)
			}
		}
	}
}

func TestDetect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		flag string
		env  map[string]string
		want Lang
	}{
		{"flag pt wins over en env", "pt", map[string]string{"LANG": "en_US.UTF-8"}, PT},
		{"flag en wins over pt env", "en", map[string]string{"LANG": "pt_BR.UTF-8"}, EN},
		{"flag pt-BR variant", "pt-BR", nil, PT},
		{"flag empty uses LANG pt", "", map[string]string{"LANG": "pt_BR.UTF-8"}, PT},
		{"flag empty uses LC_ALL pt", "", map[string]string{"LC_ALL": "pt_BR.UTF-8"}, PT},
		{"LC_ALL wins over LANG", "", map[string]string{"LC_ALL": "en_US.UTF-8", "LANG": "pt_BR.UTF-8"}, EN},
		{"no flag no env defaults EN", "", nil, EN},
		{"unknown flag falls back EN", "fr", nil, EN},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			getEnv := func(k string) string { return tt.env[k] }
			if got := Detect(tt.flag, getEnv); got != tt.want {
				t.Errorf("Detect(%q) = %s, want %s", tt.flag, got, tt.want)
			}
		})
	}
}

func TestT(t *testing.T) {
	t.Parallel()

	if got := T(EN, "err.noDomain"); !strings.Contains(got, "exposcan example.com") {
		t.Errorf("EN err.noDomain = %q, want example.com hint", got)
	}
	if got := T(PT, "err.noDomain"); !strings.Contains(got, "exemplo.com") {
		t.Errorf("PT err.noDomain = %q, want exemplo.com hint", got)
	}
	if got := T(EN, "msg.scanning", "example.com"); !strings.Contains(got, "example.com") {
		t.Errorf("args not formatted: %q", got)
	}
	// Unknown language falls back to EN instead of failing silently.
	if got := T("xx", "err.noDomain"); !strings.Contains(got, "example.com") {
		t.Errorf("fallback to EN failed: %q", got)
	}
	if got := T(EN, "does.not.exist"); got != "[missing:does.not.exist]" {
		t.Errorf("missing key should be loud, got %q", got)
	}
}
