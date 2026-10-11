package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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
