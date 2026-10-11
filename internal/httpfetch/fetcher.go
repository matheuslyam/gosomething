// Package httpfetch fetches HTTP response headers behind a small interface,
// with timeout classification and HTTPS→HTTP fallback helpers shared by the
// scan orchestrator.
package httpfetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// HTTPResult carries what a fetch observed. Status and FinalURL are kept
// because "site down" vs "404 with headers" vs "http fallback" need them;
// the body itself is always discarded (headers only).
type HTTPResult struct {
	Header   http.Header
	Status   int
	FinalURL string
}

// Fetcher abstracts header fetching for testability.
type Fetcher interface {
	Fetch(ctx context.Context, url string) (HTTPResult, error)
}

// ClientFetcher is the production Fetcher.
type ClientFetcher struct {
	client *http.Client
}

// New returns a Fetcher whose per-request timeout is already capped.
// WHY cap here instead of at call sites: the invariant "no inner timeout
// exceeds the global one" is enforced once at construction (min(10s, global)).
func New(timeout time.Duration) ClientFetcher {
	return ClientFetcher{
		client: &http.Client{
			Timeout: timeout,
			// WHY max 3 redirects + ErrUseLastResponse: avoids redirect loops
			// while still exposing the final URL for HSTS/CSP evaluation.
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// Fetch performs a GET and returns headers, status and final URL.
// WHY GET with a 1MB discard limit instead of HEAD: many servers do not
// implement HEAD; the limit prevents a malicious 10GB body from causing OOM.
func (f ClientFetcher) Fetch(ctx context.Context, url string) (HTTPResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return HTTPResult{}, err
	}
	// WHY explicit UA: some hosts block the default "Go-http-client".
	req.Header.Set("User-Agent", "exposcan/0.1 (+github.com/matheuslyam/gosomething)")
	resp, err := f.client.Do(req)
	if err != nil {
		return HTTPResult{}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	final := url
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return HTTPResult{Header: resp.Header, Status: resp.StatusCode, FinalURL: final}, nil
}

// IsTimeout reports whether err is a timeout at any wrapping layer.
// WHY os.IsTimeout + errors.As instead of only context.DeadlineExceeded:
// http.Client timeouts surface as *url.Error{Timeout:true} and dial timeouts
// as *net.OpError{Timeout:true} — neither Is DeadlineExceeded.
// NOTE: context.Canceled is deliberately NOT a timeout (manual cancel).
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if os.IsTimeout(err) {
		return true
	}
	var te interface{ Timeout() bool }
	if errors.As(err, &te) && te.Timeout() {
		return true
	}
	return false
}

// ShouldFallbackToHTTP reports whether an https fetch failure justifies
// retrying over plain http. HTTP statuses never qualify — they arrive as a
// successful HTTPResult, not an error.
func ShouldFallbackToHTTP(err error) bool {
	if err == nil {
		return false
	}
	if IsTimeout(err) {
		return true
	}
	// WHY errors.Is (not ==): dial errors wrap syscall.ECONNREFUSED several
	// layers deep (*url.Error → *net.OpError → *os.SyscallError).
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var certErr *tls.CertificateVerificationError
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &certErr) || errors.As(err, &unknownAuth) {
		return true
	}
	var tlsErr *tls.RecordHeaderError
	if errors.As(err, &tlsErr) {
		return true
	}
	// WHY also treat "connection refused" text via net.OpError: on some
	// platforms the errno mapping differs; Op is a stable signal.
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	return false
}
