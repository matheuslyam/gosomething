package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/matheuslyam/gosomething/internal/exposcan"
	"github.com/matheuslyam/gosomething/internal/httpfetch"
	"github.com/matheuslyam/gosomething/internal/i18n"
	"github.com/matheuslyam/gosomething/internal/secrets"
)

func runWith(args ...string) (int, string) {
	var buf bytes.Buffer
	code := run(args, func(string) string { return "" }, &buf)
	return code, buf.String()
}

func TestRunHelpReturns0(t *testing.T) {
	t.Parallel()

	code, out := runWith("--help")
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "Usage:") {
		t.Errorf("help missing usage, got %q", out)
	}
}

func TestRunHelpPTHasPTUsage(t *testing.T) {
	t.Parallel()

	code, out := runWith("--lang", "pt", "--help")
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "Uso:") {
		t.Errorf("expected PT usage, got %q", out)
	}
}

func TestRunParseErrReturns2(t *testing.T) {
	t.Parallel()

	if code, _ := runWith("--badflag"); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

func TestRunNArg(t *testing.T) {
	t.Parallel()

	// WHY three cases: 0 args must fail, 2+ must not silently use the first,
	// and a flag placed after the positional keeps NArg!=1 (order is fixed).
	for _, args := range [][]string{{}, {"a.com", "b.com"}, {"example.com", "--lang", "pt"}} {
		if code, _ := runWith(args...); code != 2 {
			t.Errorf("run(%v) exit = %d, want 2", args, code)
		}
	}
}

func TestRunNArgJSONEnvelope(t *testing.T) {
	t.Parallel()

	code, out := runWith("--json")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	var env ErrorEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("output is not an ErrorEnvelope: %v (%q)", err, out)
	}
	if env.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestRunBadLang(t *testing.T) {
	t.Parallel()

	if code, _ := runWith("--lang", "fr", "example.com"); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

func TestRunBadTimeout(t *testing.T) {
	t.Parallel()

	if code, _ := runWith("--timeout", "7s", "example.com"); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

func TestRunInvalidDomainNoNetwork(t *testing.T) {
	t.Parallel()

	// WHY no network here: validation rejects before Scan, so no DNS/HTTP
	// is attempted and the test stays deterministic offline.
	code, out := runWith("http://a.com")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(out, "example.com") {
		t.Errorf("expected friendly hint, got %q", out)
	}
}

func TestPeekLang(t *testing.T) {
	t.Parallel()

	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--lang", "pt", "example.com"}, "pt"},
		{[]string{"--lang=pt", "example.com"}, "pt"},
		{[]string{"example.com"}, ""},
		{[]string{}, ""},
	}
	for _, tt := range cases {
		if got := peekLang(tt.args); got != tt.want {
			t.Errorf("peekLang(%v) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

func TestRunRevealWithoutSecretsReturns2(t *testing.T) {
	t.Parallel()

	// WHY usage error: --reveal alone would silently do nothing in the
	// normal scan; failing loud prevents training a leak-by-default habit.
	if code, _ := runWith("--reveal", "example.com"); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if code, _ := runWith("-rv", "example.com"); code != 2 {
		t.Errorf("exit = %d, want 2 for -rv alias", code)
	}
}

func TestRunSecretsInvalidDomainNoNetwork(t *testing.T) {
	t.Parallel()

	// WHY no network: validation rejects before any fetch.
	if code, _ := runWith("--secrets", "http://a.com"); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

type stubSecretsBody struct {
	html string
	js   map[string]string
	err  map[string]error
}

func (s stubSecretsBody) FetchBody(_ context.Context, url string) (httpfetch.BodyResult, error) {
	if err, ok := s.err[url]; ok {
		return httpfetch.BodyResult{}, err
	}
	if b, ok := s.js[url]; ok {
		return httpfetch.BodyResult{Body: []byte(b), FinalURL: url}, nil
	}
	return httpfetch.BodyResult{Body: []byte(s.html), FinalURL: url}, nil
}

func secretsDepsWith(html string, js map[string]string) secrets.Deps {
	return secrets.Deps{Fetch: stubSecretsBody{html: html, js: js}}
}

// TestRunSecretsExits proves the feature contract (QA round 1, SC-01/GO-02):
// findings → 3 masked by default, clean → 0, total failure → 1.
func TestRunSecretsExits(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	js := map[string]string{"https://example.com/app.js": `var k = "AKIAIOSFODNN7EXAMPLE";`}
	html := `<html><head><script src="/app.js"></script></head></html>`

	var buf bytes.Buffer
	if code := runSecretsWith(ctx, &buf, i18n.EN, false, "example.com", "example.com", secretsDepsWith(html, js), false); code != 3 {
		t.Errorf("with findings exit = %d, want 3", code)
	}
	out := buf.String()
	if !strings.Contains(out, "AWSAccessKey") {
		t.Errorf("human must show the pattern name, got %q", out)
	}
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("default must mask the full value, got %q", out)
	}

	buf.Reset()
	if code := runSecretsWith(ctx, &buf, i18n.EN, false, "example.com", "example.com", secretsDepsWith("<html></html>", nil), false); code != 0 {
		t.Errorf("clean exit = %d, want 0", code)
	}

	buf.Reset()
	fail := secrets.Deps{Fetch: stubSecretsBody{err: map[string]error{
		"https://example.com": errors.New("boom"),
		"http://example.com":  errors.New("boom"),
	}}}
	if code := runSecretsWith(ctx, &buf, i18n.EN, false, "example.com", "example.com", fail, false); code != 1 {
		t.Errorf("total failure exit = %d, want 1", code)
	}
}

func TestPrintHumanCookiesMaskedByDefault(t *testing.T) {
	t.Parallel()

	res := exposcan.Result{
		Domain: "example.com", IPs: []string{},
		Ports:   map[int]bool{80: false, 443: false},
		Headers: map[string]string{}, Cookies: []string{"session=AbCdEfGh1234; Path=/; Secure"},
		Reasons: map[string]string{"cdn": "no signal", "waf": "no signal", "hsts": "not evaluated (http)", "csp": "not evaluated (http)", "server": "absent"},
	}
	var buf bytes.Buffer
	printHuman(&buf, i18n.EN, res, false, false)
	out := buf.String()
	if !strings.Contains(out, "session=AbCd…1234; Path=/; Secure") {
		t.Errorf("expected masked cookie, got %q", out)
	}
	if strings.Contains(out, "AbCdEfGh1234") {
		t.Errorf("full value leaked in default output: %q", out)
	}
	if strings.Contains(out, "why cdn:") {
		t.Errorf("verbose section must not print without --verbose: %q", out)
	}

	buf.Reset()
	printHuman(&buf, i18n.EN, res, true, true)
	out = buf.String()
	if !strings.Contains(out, "session=AbCdEfGh1234; Path=/; Secure") {
		t.Errorf("expected full cookie with --show-cookies, got %q", out)
	}
	if !strings.Contains(out, "cdn: no signal") {
		t.Errorf("expected why section with --verbose, got %q", out)
	}
}

func TestErrorEnvelopeJSON(t *testing.T) {
	t.Parallel()

	raw, _ := json.Marshal(ErrorEnvelope{Domain: "x", Error: "y"})
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m["domain"] != "x" || m["error"] != "y" {
		t.Errorf("unexpected envelope shape: %s", raw)
	}
}
