package httpfetch

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestFetchSuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Test", "yes")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New(5*time.Second).Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if res.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", res.Status)
	}
	if res.Header.Get("X-Test") != "yes" {
		t.Errorf("missing test header: %v", res.Header)
	}
	if res.FinalURL == "" {
		t.Error("expected non-empty FinalURL")
	}
}

func TestFetch404IsNotAnError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// WHY: statuses are data (HTTPResult), not errors — only transport
	// failures justify the https→http fallback, never a status code.
	res, err := New(5*time.Second).Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("404 must not be an error, got: %v", err)
	}
	if res.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", res.Status)
	}
}

func TestFetchTimeout(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	_, err := New(50*time.Millisecond).Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !IsTimeout(err) {
		t.Errorf("expected IsTimeout, got: %v", err)
	}
}

func TestIsTimeoutMatrix(t *testing.T) {
	t.Parallel()

	timeoutErr := &os.SyscallError{Syscall: "read", Err: syscall.ETIMEDOUT}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"deadline exceeded", context.DeadlineExceeded, true},
		{"canceled is not timeout", context.Canceled, false},
		{"os timeout", timeoutErr, true},
		{"url timeout", &urlError{timeout: true}, true},
		{"op timeout", &net.OpError{Op: "dial", Err: timeoutErr}, true},
		{"generic", errors.New("boom"), false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsTimeout(tt.err); got != tt.want {
				t.Errorf("IsTimeout(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// urlError mimics *url.Error without importing net/url for the assertion.
type urlError struct{ timeout bool }

func (e *urlError) Error() string { return "url error" }
func (e *urlError) Timeout() bool { return e.timeout }

func TestShouldFallback(t *testing.T) {
	t.Parallel()

	refused := &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"timeout", context.DeadlineExceeded, true},
		{"refused", refused, true},
		{"generic", errors.New("boom"), false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ShouldFallbackToHTTP(tt.err); got != tt.want {
				t.Errorf("ShouldFallbackToHTTP(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
