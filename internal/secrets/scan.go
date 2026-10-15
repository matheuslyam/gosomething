package secrets

import (
	"context"
	"fmt"
	"strings"

	"github.com/matheuslyam/gosomething/internal/httpfetch"
)

// Finding is one masked secret hit. Value is only populated with --reveal;
// otherwise it is omitted from JSON via omitempty so logs never carry it.
type Finding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Pattern string `json:"pattern"`
	Masked  string `json:"masked"`
	Value   string `json:"value,omitempty"`
}

// SecretsResult is the JSON-stable outcome of a --secrets scan.
// Findings is always initialized (never null). FilesScanned counts external
// .js files actually scanned (0-10); the initial HTML and inline blocks are
// always scanned at zero extra fetch cost and are not counted here.
// Truncated is true when srcs exceeded MaxScripts or any body hit the 2MB cap.
type SecretsResult struct {
	Domain       string    `json:"domain"`
	Punycode     string    `json:"punycode"`
	FilesScanned int       `json:"filesScanned"`
	Findings     []Finding `json:"findings"`
	Truncated    bool      `json:"truncated"`
}

// Deps carries the body fetcher. An interface (not a concrete type) keeps
// Scan testable with stubs and free of real network in unit tests.
type Deps struct {
	Fetch httpfetch.BodyFetcher
}

// Scan hunts secrets best-effort: fetch HTML (https with fallback to http
// only on transport failure, never on status), scan HTML + inline scripts,
// then up to MaxScripts external .js (same-origin first).
// A non-nil error means nothing usable was collected (HTML fetch failed or
// the context expired). Single .js failures are skipped, never fatal.
// WHY sequential .js fetches: 10 parallel fetches burst third parties and
// complicate truncation; sequential under the shared global ctx still fits
// 15s for small bundles.
func Scan(ctx context.Context, domain, punycode string, deps Deps, reveal bool) (SecretsResult, error) {
	res := SecretsResult{
		Domain:   domain,
		Punycode: punycode,
		Findings: []Finding{},
	}

	htmlBody, baseURL, truncated, err := fetchHTML(ctx, punycode, deps.Fetch)
	if err != nil {
		return SecretsResult{}, err
	}
	if truncated {
		res.Truncated = true
	}

	// WHY scan the HTML itself: secrets hide in meta tags, comments and data
	// attributes outside <script>; the body is already downloaded, zero cost.
	res.Findings = append(res.Findings, scanContent("(html)", string(htmlBody), reveal)...)

	inlines, rawSrcs := ExtractScripts(htmlBody)
	for i, inline := range inlines {
		if err := ctx.Err(); err != nil {
			return SecretsResult{}, err
		}
		name := fmt.Sprintf("(inline #%d)", i+1)
		res.Findings = append(res.Findings, scanContent(name, inline, reveal)...)
	}

	ordered, tooMany := SplitScripts(rawSrcs, baseURL)
	if tooMany {
		res.Truncated = true
	}
	for _, jsURL := range ordered {
		if err := ctx.Err(); err != nil {
			return SecretsResult{}, err
		}
		body, err := deps.Fetch.FetchBody(ctx, jsURL)
		if err != nil {
			// WHY skip single-file failures: one dead bundle must not abort
			// the other nine; the HTML+inline findings remain valuable.
			continue
		}
		if body.Truncated {
			res.Truncated = true
		}
		file := body.FinalURL
		if file == "" {
			file = jsURL
		}
		res.Findings = append(res.Findings, scanContent(file, string(body.Body), reveal)...)
		res.FilesScanned++
	}

	if err := ctx.Err(); err != nil {
		return SecretsResult{}, err
	}
	return res, nil
}

// fetchHTML gets the page body trying https first, then http on transport
// failure (same predicate as the main scan — statuses never qualify).
func fetchHTML(ctx context.Context, punycode string, f httpfetch.BodyFetcher) ([]byte, string, bool, error) {
	body, err := f.FetchBody(ctx, "https://"+punycode)
	if err != nil && httpfetch.ShouldFallbackToHTTP(err) {
		body, err = f.FetchBody(ctx, "http://"+punycode)
	}
	if err != nil {
		return nil, "", false, fmt.Errorf("fetch %s: %w", punycode, err)
	}
	base := body.FinalURL
	if base == "" {
		base = "https://" + punycode
	}
	return body.Body, base, body.Truncated, nil
}

// scanContent runs every pattern over content line by line (1-indexed).
func scanContent(file, content string, reveal bool) []Finding {
	var out []Finding
	for i, line := range strings.Split(content, "\n") {
		for _, m := range matchLine(line) {
			f := Finding{
				File:    file,
				Line:    i + 1,
				Pattern: m.pattern,
				Masked:  Mask(m.value),
			}
			// WHY gate full value behind reveal: default output must be safe
			// to paste into issues/videos; only an explicit flag leaks it.
			if reveal {
				f.Value = m.value
			}
			out = append(out, f)
		}
	}
	return out
}
