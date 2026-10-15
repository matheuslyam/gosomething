package httpfetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchBodySuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	res, err := New(5*time.Second).FetchBody(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchBody error: %v", err)
	}
	if string(res.Body) != "hello" {
		t.Errorf("body = %q, want hello", res.Body)
	}
	if res.Truncated {
		t.Error("small body must not truncate")
	}
}

func TestFetchBodyTruncatesAt2MB(t *testing.T) {
	t.Parallel()

	big := strings.Repeat("a", MaxSecretsBody+100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	res, err := New(5*time.Second).FetchBody(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchBody error: %v", err)
	}
	if !res.Truncated || len(res.Body) != MaxSecretsBody {
		t.Errorf("want truncated 2MB, got len=%d trunc=%v", len(res.Body), res.Truncated)
	}
}
