package secrets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matheuslyam/gosomething/internal/httpfetch"
)

// TestIntegrationLocalhostFixture is the handoff acceptance: a local test
// page with a fake key must be caught; without the key it must be clean.
// WHY httptest + dynamic ports: no real network in tests except localhost,
// never fixed 80/443.
func TestIntegrationLocalhostFixture(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><head><script src="/app.js"></script></head><body>hi</body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`var k = "AKIAIOSFODNN7EXAMPLE";`))
	})
	mux.HandleFunc("/clean.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`var a = 1;`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	fetch := httpfetch.New(5 * time.Second)
	ctx := context.Background()

	// With fake key: fetch HTML then JS manually (same steps as Scan, but
	// against the localhost fixture URL instead of a public domain).
	htmlBody, err := fetch.FetchBody(ctx, srv.URL)
	if err != nil {
		t.Fatalf("fixture HTML fetch: %v", err)
	}
	jsBody, err := fetch.FetchBody(ctx, srv.URL+"/app.js")
	if err != nil {
		t.Fatalf("fixture JS fetch: %v", err)
	}
	combined := string(htmlBody.Body) + "\n" + string(jsBody.Body)
	if len(matchLine(combined)) == 0 {
		t.Error("fixture with fake key must produce at least one finding")
	}

	cleanBody, err := fetch.FetchBody(ctx, srv.URL+"/clean.js")
	if err != nil {
		t.Fatalf("clean JS fetch: %v", err)
	}
	if len(matchLine(string(cleanBody.Body))) != 0 {
		t.Error("clean fixture must produce zero findings")
	}
	if !strings.Contains(string(htmlBody.Body), "/app.js") {
		t.Error("fixture HTML must reference /app.js")
	}
}
