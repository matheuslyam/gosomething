// Package cdn heuristically identifies CDN providers from a CNAME and HTTP
// response headers. Detection is best-effort (no ASN database in v1);
// anything without a known signal returns "unknown".
package cdn

import (
	"net/http"
	"strings"
)

// Detect returns the provider name plus the reason that fired, for verbose
// output. Reasons name the exact signal ("cname suffix .cloudflare.net",
// "header cf-ray") or "no signal".
//
// All CNAME matching is HasSuffix on the lowercased, dot-trimmed name (never
// Contains — "notakamai.com" must not match). Header lookup uses Get, which
// is already case-insensitive, so no manual lowering of keys.
func Detect(cname string, h http.Header) (string, string) {
	c := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
	suffix := func(suffixes ...string) (string, bool) {
		for _, s := range suffixes {
			if strings.HasSuffix(c, s) {
				return s, true
			}
		}
		return "", false
	}
	header := func(keys ...string) (string, bool) {
		for _, k := range keys {
			if h.Get(k) != "" {
				return strings.ToLower(k), true
			}
		}
		return "", false
	}
	// WHY sequential ifs (not else-if): a present-but-unmatched signal
	// (e.g. X-Served-By without "cache-") must not block later checks.
	if s, ok := suffix(".cloudflare.net"); ok {
		return "Cloudflare", "cname suffix " + s
	}
	if k, ok := header("Cf-Ray"); ok {
		return "Cloudflare", "header " + k
	}
	if s, ok := suffix(".cloudfront.net"); ok {
		return "CloudFront", "cname suffix " + s
	}
	if k, ok := header("X-Amz-Cf-Id"); ok {
		return "CloudFront", "header " + k
	}
	if s, ok := suffix(".akamai.net", ".akamaized.net"); ok {
		return "Akamai", "cname suffix " + s
	}
	if s, ok := suffix(".fastly.net"); ok {
		return "Fastly", "cname suffix " + s
	}
	if k, ok := header("X-Served-By"); ok {
		// WHY Contains (not Prefix) for x-served-by: edge POP names vary
		// ("cache-iad-kjyo" vs "cache-..."), only "cache-" is stable.
		if strings.Contains(strings.ToLower(h.Get("X-Served-By")), "cache-") {
			return "Fastly", "header " + k
		}
	}
	if s, ok := suffix(".sucuri.net"); ok {
		return "Sucuri", "cname suffix " + s
	}
	if k, ok := header("X-Sucuri-Id"); ok {
		return "Sucuri", "header " + k
	}
	if s, ok := suffix(".incapsula.com"); ok {
		return "Incapsula", "cname suffix " + s
	}
	if k, ok := header("X-Iinfo"); ok {
		return "Incapsula", "header " + k
	}
	if s, ok := suffix(".ddos-guard.net"); ok {
		return "DDoS-Guard", "cname suffix " + s
	}
	if k, ok := header("X-Ddos-Guard"); ok {
		return "DDoS-Guard", "header " + k
	}
	return "unknown", "no signal"
}
