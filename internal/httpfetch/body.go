// Body fetching for the --secrets mode: full response bodies with a hard cap.
package httpfetch

import (
	"context"
	"io"
	"net/http"
)

// MaxSecretsBody is the per-file ceiling for --secrets downloads.
// WHY 2MB: frontend bundles are often 200KB-1MB; 2MB catches real bundles
// while a malicious 10GB body cannot cause OOM. Truncation is reported via
// BodyResult.Truncated instead of failing, so the prefix is still scanned.
const MaxSecretsBody = 2 << 20

// BodyResult carries a fetched body plus its final URL after redirects.
// Truncated is true when the body was cut at MaxSecretsBody.
type BodyResult struct {
	Body      []byte
	FinalURL  string
	Status    int
	Truncated bool
}

// BodyFetcher abstracts body fetching for testability.
type BodyFetcher interface {
	FetchBody(ctx context.Context, url string) (BodyResult, error)
}

// FetchBody performs a GET and returns up to MaxSecretsBody bytes.
// WHY GET (not HEAD): secrets live in bodies; status codes are data, not
// errors — even a 404 page is scanned. Transport failures return an error.
// WHY reuses f.client: the invariant "no inner timeout exceeds global" is
// already enforced at construction via New(min(10s, global)).
func (f ClientFetcher) FetchBody(ctx context.Context, url string) (BodyResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return BodyResult{}, err
	}
	// WHY explicit UA: some hosts block the default "Go-http-client".
	req.Header.Set("User-Agent", "exposcan/0.1 (+github.com/matheuslyam/gosomething)")
	resp, err := f.client.Do(req)
	if err != nil {
		return BodyResult{}, err
	}
	defer resp.Body.Close()
	// WHY +1 byte: reading Max+1 distinguishes "exactly 2MB" (not truncated)
	// from "more than 2MB" (truncated) without a second request.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxSecretsBody+1))
	if err != nil {
		return BodyResult{}, err
	}
	truncated := false
	if len(raw) > MaxSecretsBody {
		raw = raw[:MaxSecretsBody]
		truncated = true
	}
	final := url
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return BodyResult{Body: raw, FinalURL: final, Status: resp.StatusCode, Truncated: truncated}, nil
}
