package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/matheuslyam/gosomething/internal/httpfetch"
)

type stubBody struct {
	bodies map[string]httpfetch.BodyResult
	err    map[string]error
}

func (s stubBody) FetchBody(_ context.Context, url string) (httpfetch.BodyResult, error) {
	if err, ok := s.err[url]; ok {
		return httpfetch.BodyResult{}, err
	}
	if b, ok := s.bodies[url]; ok {
		return b, nil
	}
	return httpfetch.BodyResult{}, errors.New("not found: " + url)
}

func TestScanWithFakeKey(t *testing.T) {
	t.Parallel()

	// WHY fake AWS example key: valid shape, zero real-world value.
	html := `<html><head><script src="/app.js"></script></head><body>hi</body></html>`
	js := `var k = "AKIAIOSFODNN7EXAMPLE";`
	deps := Deps{Fetch: stubBody{bodies: map[string]httpfetch.BodyResult{
		"https://example.com":        {Body: []byte(html), FinalURL: "https://example.com/"},
		"https://example.com/app.js": {Body: []byte(js), FinalURL: "https://example.com/app.js"},
	}}}
	res, err := Scan(context.Background(), "example.com", "example.com", deps, false)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Pattern != "AWSAccessKey" {
		t.Fatalf("findings = %+v, want 1 AWSAccessKey", res.Findings)
	}
	if res.FilesScanned != 1 {
		t.Errorf("filesScanned = %d, want 1", res.FilesScanned)
	}
	if res.Findings[0].Value != "" {
		t.Error("default must not carry the full value")
	}
	if strings.Contains(res.Findings[0].Masked, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("masked must not equal the full value")
	}
}

func TestScanReveal(t *testing.T) {
	t.Parallel()

	html := `secret="12345678"`
	deps := Deps{Fetch: stubBody{bodies: map[string]httpfetch.BodyResult{
		"https://example.com": {Body: []byte(html), FinalURL: "https://example.com/"},
	}}}
	res, err := Scan(context.Background(), "example.com", "example.com", deps, true)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Value == "" {
		t.Fatalf("reveal must populate Value, got %+v", res.Findings)
	}
}

func TestScanClean(t *testing.T) {
	t.Parallel()

	html := `<html><head></head><body>hello</body></html>`
	deps := Deps{Fetch: stubBody{bodies: map[string]httpfetch.BodyResult{
		"https://example.com": {Body: []byte(html), FinalURL: "https://example.com/"},
	}}}
	res, err := Scan(context.Background(), "example.com", "example.com", deps, false)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("clean page must have no findings, got %+v", res.Findings)
	}
	if res.Findings == nil {
		t.Error("findings must be initialized, not nil")
	}
}

func TestScanInlineAndHTML(t *testing.T) {
	t.Parallel()

	html := `<html><!-- api_key="12345678" --><script>var secret="12345678"</script></html>`
	deps := Deps{Fetch: stubBody{bodies: map[string]httpfetch.BodyResult{
		"https://example.com": {Body: []byte(html), FinalURL: "https://example.com/"},
	}}}
	res, err := Scan(context.Background(), "example.com", "example.com", deps, false)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(res.Findings) < 2 {
		t.Errorf("HTML comment + inline must both hit, got %+v", res.Findings)
	}
}

func TestScanThirdPartyIncluded(t *testing.T) {
	t.Parallel()

	// WHY still localhost-shaped third party: no real network in tests
	// except localhost; a different localhost port models "third party".
	html := `<html><head><script src="http://third.invalid/ext.js"></script></head></html>`
	js := `ghp_123456789012345678901234567890123456`
	deps := Deps{Fetch: stubBody{bodies: map[string]httpfetch.BodyResult{
		"https://example.com":         {Body: []byte(html), FinalURL: "https://example.com/"},
		"http://third.invalid/ext.js": {Body: []byte(js), FinalURL: "http://third.invalid/ext.js"},
	}}}
	res, err := Scan(context.Background(), "example.com", "example.com", deps, false)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Pattern == "GitHubToken" {
			found = true
		}
	}
	if !found {
		t.Errorf("third-party JS must be scanned, got %+v", res.Findings)
	}
}

func TestScanSingleJSFailureSkipped(t *testing.T) {
	t.Parallel()

	html := `<html><head><script src="/dead.js"></script></head><body>secret="12345678"</body></html>`
	deps := Deps{
		Fetch: stubBody{
			bodies: map[string]httpfetch.BodyResult{
				"https://example.com": {Body: []byte(html), FinalURL: "https://example.com/"},
			},
			err: map[string]error{"https://example.com/dead.js": errors.New("boom")},
		},
	}
	res, err := Scan(context.Background(), "example.com", "example.com", deps, false)
	if err != nil {
		t.Fatalf("single JS failure must be skipped, got: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Error("HTML finding must survive a dead JS file")
	}
}

func TestScanHTMLFailureIsFatal(t *testing.T) {
	t.Parallel()

	deps := Deps{Fetch: stubBody{err: map[string]error{
		"https://example.com": errors.New("boom"),
		"http://example.com":  errors.New("boom"),
	}}}
	if _, err := Scan(context.Background(), "example.com", "example.com", deps, false); err == nil {
		t.Error("HTML fetch failure must return an error")
	}
}

func TestScanCanceledContext(t *testing.T) {
	t.Parallel()

	// WHY mirrors exposcan.TestScanCanceledContext: mid-process
	// cancellation is an SC-02 exception flow and must error, never a
	// silent clean result (QA round 1).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := Deps{Fetch: stubBody{bodies: map[string]httpfetch.BodyResult{
		"https://example.com": {Body: []byte("hi"), FinalURL: "https://example.com/"},
	}}}
	if _, err := Scan(ctx, "example.com", "example.com", deps, false); err == nil {
		t.Error("expected error with canceled context")
	}
}

func TestScanTruncatesAt11Scripts(t *testing.T) {
	t.Parallel()

	// WHY Scan-level (not just Split-level): Truncated/FilesScanned wiring
	// is output contract (SC-01) and only a full Scan proves it (QA round 1).
	var html strings.Builder
	html.WriteString("<html><head>")
	bodies := map[string]httpfetch.BodyResult{}
	for i := 0; i < 11; i++ {
		name := "a" + string(rune('a'+i)) + ".js"
		html.WriteString(`<script src="/` + name + `"></script>`)
		bodies["https://example.com/"+name] = httpfetch.BodyResult{
			Body:     []byte("var a = 1;"),
			FinalURL: "https://example.com/" + name,
		}
	}
	html.WriteString("</head><body>hi</body></html>")
	bodies["https://example.com"] = httpfetch.BodyResult{
		Body:     []byte(html.String()),
		FinalURL: "https://example.com/",
	}
	res, err := Scan(context.Background(), "example.com", "example.com", Deps{Fetch: stubBody{bodies: bodies}}, false)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if !res.Truncated {
		t.Error("11 scripts must set truncated")
	}
	if res.FilesScanned != 10 {
		t.Errorf("filesScanned = %d, want 10", res.FilesScanned)
	}
}

func TestScanSecretsBundle(t *testing.T) {
	t.Parallel()

	// WHY one bundle with three families: proves Scan wires every new
	// pattern class end-to-end (phase-1 acceptance: github_pat_ and
	// service_role fixtures). Values are fake.
	js := "const t = \"github_pat_" + strings.Repeat("a", 82) + "\";\n" +
		"const sr = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"; // service_role\n" +
		"const cfg = {\"apiKey\": \"fakesecret123456\"};\n"
	// WHY HTML references /app.js: Scan only fetches JS listed in <script src>.
	deps := Deps{Fetch: stubBody{bodies: map[string]httpfetch.BodyResult{
		"https://example.com": {
			Body:     []byte(`<html><head><script src="/app.js"></script></head></html>`),
			FinalURL: "https://example.com/",
		},
		"https://example.com/app.js": {Body: []byte(js), FinalURL: "https://example.com/app.js"},
	}}}
	res, err := Scan(context.Background(), "example.com", "example.com", deps, false)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	want := map[string]bool{"GitHubFineGrained": false, "JWT": false, "APIKey": false}
	for _, f := range res.Findings {
		want[f.Pattern] = true
	}
	for p, hit := range want {
		if !hit {
			t.Errorf("bundle missing %s, got %+v", p, res.Findings)
		}
	}
}

func TestSecretsResultJSONStable(t *testing.T) {
	t.Parallel()

	deps := Deps{Fetch: stubBody{bodies: map[string]httpfetch.BodyResult{
		"https://example.com": {Body: []byte("hi"), FinalURL: "https://example.com/"},
	}}}
	res, err := Scan(context.Background(), "example.com", "example.com", deps, false)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	raw, _ := json.Marshal(res)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"domain", "punycode", "filesScanned", "findings", "truncated"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing JSON key %q in %s", k, raw)
		}
	}
}
