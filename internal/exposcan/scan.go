// Package exposcan orchestrates a domain exposure scan: DNS, HTTP headers,
// CDN and WAF heuristics and TCP port probes, all bounded by the caller's context.
package exposcan

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/matheuslyam/gosomething/internal/cdn"
	"github.com/matheuslyam/gosomething/internal/dns"
	"github.com/matheuslyam/gosomething/internal/httpfetch"
	"github.com/matheuslyam/gosomething/internal/ports"
	"github.com/matheuslyam/gosomething/internal/waf"
)

// Deps carries the scan collaborators. Interfaces (not concrete types) keep
// Scan testable with stubs and free of real network in unit tests.
type Deps struct {
	DNS  dns.Resolver
	HTTP httpfetch.Fetcher
	Dial ports.Dialer
}

// headerAllowlist is the only set of response headers whose values are kept.
// WHY allowlist instead of dumping everything: values like Server prove
// exposure (FIRST.md asks for sensitive headers), while Set-Cookie values
// would leak sessions into output/JSON — presence only, never the value.
var headerAllowlist = []string{"Server", "X-Powered-By", "Via", "Cf-Ray", "X-Amz-Cf-Id"}

// Result is the JSON-stable scan outcome. Slices and maps are always
// initialized (never null) and Ports always carries 80 and 443 so the JSON
// shape never depends on the outcome.
type Result struct {
	Domain        string            `json:"domain"`
	Punycode      string            `json:"punycode"`
	IPs           []string          `json:"ips"`
	CNAME         string            `json:"cname"`
	CDN           string            `json:"cdn"`
	WAF           string            `json:"waf"`
	ASNs          []dns.ASNRecord   `json:"asns"`
	Ports         map[int]bool      `json:"ports"`
	Headers       map[string]string `json:"headers"`
	HSTS          bool              `json:"hsts"`
	CSP           bool              `json:"csp"`
	HasSetCookie  bool              `json:"hasSetCookie"`
	Cookies       []string          `json:"cookies"`
	ServerPresent bool              `json:"serverPresent"`
	Reasons       map[string]string `json:"reasons"`
	HTTPStatus    int               `json:"httpStatus"`
	FinalURL      string            `json:"finalUrl"`
	HTTPError     string            `json:"httpError,omitempty"`
}

// Scan runs the full probe sequence best-effort: DNS, HTTP (https with
// fallback to http only on transport failure, never on status), CDN
// detection, then ports. HTTP failure never aborts the scan when DNS
// succeeded — the partial Result carries HTTPError as a visible warning.
// A non-nil error means nothing usable was collected (DNS failure or an
// expired/canceled context).
func Scan(ctx context.Context, domain, punycode string, deps Deps) (Result, error) {
	res := Result{
		Domain:   domain,
		Punycode: punycode,
		IPs:      []string{},
		Ports:    map[int]bool{80: false, 443: false},
		Headers:  map[string]string{},
		CDN:      "unknown",
		WAF:      "unknown",
		ASNs:     []dns.ASNRecord{},
		Cookies:  []string{},
		Reasons:  map[string]string{},
	}
	ips, err := deps.DNS.LookupIPs(ctx, punycode)
	if err != nil {
		return Result{}, fmt.Errorf("dns lookup %s: %w", punycode, err)
	}
	for _, ip := range ips {
		res.IPs = append(res.IPs, ip.String())
	}
	// WHY indexed slots instead of mutex-append: per-IP parallelism with a
	// fixed index per IP keeps output order deterministic (same order as
	// IPs) without a post-hoc sort, so tests assert exact sequences.
	// WHY failure tolerated: enrichment is best-effort (like CNAME); only
	// the IP set is fatal. Every IP stays accounted for via UnknownASN.
	asnSlots := make([][]dns.ASNRecord, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recs, err := deps.DNS.LookupASN(ctx, ip)
			if err != nil {
				recs = []dns.ASNRecord{dns.UnknownASN(ip)}
			}
			asnSlots[i] = recs
		}()
	}
	wg.Wait()
	for _, recs := range asnSlots {
		res.ASNs = append(res.ASNs, recs...)
	}
	// WHY CNAME failure tolerated: a missing CNAME is normal (apex domains);
	// only the IP set is fatal.
	if cname, err := deps.DNS.LookupCNAME(ctx, punycode); err == nil {
		res.CNAME = strings.TrimSuffix(cname, ".")
	}

	httpRes, httpErr := deps.HTTP.Fetch(ctx, "https://"+punycode)
	if httpErr != nil && httpfetch.ShouldFallbackToHTTP(httpErr) {
		firstErr := httpErr
		httpRes, httpErr = deps.HTTP.Fetch(ctx, "http://"+punycode)
		if httpErr == nil {
			// WHY preserve the first error: a silent cert→http downgrade
			// would hide a security problem; the warning stays visible
			// while the scan still reports what http revealed.
			res.HTTPError = "https: " + firstErr.Error()
		}
	}
	if httpErr == nil {
		applyHTTP(&res, httpRes)
	} else {
		if res.HTTPError == "" {
			res.HTTPError = httpErr.Error()
		} else {
			res.HTTPError += "; http: " + httpErr.Error()
		}
		res.CDN, res.Reasons["cdn"] = cdn.Detect(res.CNAME, nil)
		res.WAF, res.Reasons["waf"] = waf.Detect(res.CNAME, nil)
		// WHY explicit here too: Reasons keys are deterministic (always
		// cdn/waf/hsts/csp/server) so verbose output and JSON never depend
		// on which path ran.
		res.Reasons["hsts"] = "not evaluated (no fetch)"
		res.Reasons["csp"] = "not evaluated (no fetch)"
		res.Reasons["server"] = "absent"
	}

	for p, open := range ports.Check(ctx, punycode, []int{80, 443}, deps.Dial) {
		res.Ports[p] = open
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return res, nil
}

// applyHTTP folds a successful fetch into res.
func applyHTTP(res *Result, httpRes httpfetch.HTTPResult) {
	res.HTTPStatus = httpRes.Status
	res.FinalURL = httpRes.FinalURL
	for _, k := range headerAllowlist {
		if v := httpRes.Header.Get(k); v != "" {
			res.Headers[strings.ToLower(k)] = v
		}
	}
	if _, ok := httpRes.Header["Set-Cookie"]; ok {
		res.HasSetCookie = true
	}
	// WHY raw capture here, masking at render: Scan owns collection (like
	// Headers), presentation owns redaction; the --show-cookies flag then
	// decides at the edge, and JSON follows the same rule as human output.
	for _, c := range httpRes.Header["Set-Cookie"] {
		res.Cookies = append(res.Cookies, c)
	}
	res.ServerPresent = res.Headers["server"] != "" || res.Headers["x-powered-by"] != ""
	// WHY https-only: HSTS/CSP are meaningful for TLS responses; an http
	// fallback reporting them would be misleading, so they stay false there.
	if strings.HasPrefix(strings.ToLower(httpRes.FinalURL), "https://") {
		res.HSTS = httpRes.Header.Get("Strict-Transport-Security") != ""
		res.CSP = httpRes.Header.Get("Content-Security-Policy") != ""
	}
	res.CDN, res.Reasons["cdn"] = cdn.Detect(res.CNAME, httpRes.Header)
	res.WAF, res.Reasons["waf"] = waf.Detect(res.CNAME, httpRes.Header)
	isHTTPS := strings.HasPrefix(strings.ToLower(httpRes.FinalURL), "https://")
	// WHY explicit reasons instead of re-deriving in main: the rule lives
	// once, beside the flag it explains; verbose output only prints them.
	res.Reasons["hsts"] = "not evaluated (http)"
	res.Reasons["csp"] = "not evaluated (http)"
	if isHTTPS {
		res.Reasons["hsts"] = "strict-transport-security absent (https)"
		if res.HSTS {
			res.Reasons["hsts"] = "strict-transport-security present (https)"
		}
		res.Reasons["csp"] = "content-security-policy absent (https)"
		if res.CSP {
			res.Reasons["csp"] = "content-security-policy present (https)"
		}
	}
	res.Reasons["server"] = "absent"
	if res.ServerPresent {
		res.Reasons["server"] = "server|x-powered-by present"
	}
}
