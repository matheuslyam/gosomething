// Package cdn heuristically identifies CDN providers from a CNAME and HTTP
// response headers. Detection is best-effort (no ASN database in v1);
// anything without a known signal returns "unknown".
package cdn

import (
	"net/http"
	"strings"
)

// Detect returns the provider name or "unknown".
//
// All CNAME matching is HasSuffix on the lowercased, dot-trimmed name (never
// Contains — "notakamai.com" must not match). Header lookup uses Get, which
// is already case-insensitive, so no manual lowering of keys.
func Detect(cname string, h http.Header) string {
	c := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
	hasSuffix := func(suffixes ...string) bool {
		for _, s := range suffixes {
			if strings.HasSuffix(c, s) {
				return true
			}
		}
		return false
	}
	switch {
	case hasSuffix(".cloudflare.net") || h.Get("Cf-Ray") != "":
		return "Cloudflare"
	case hasSuffix(".cloudfront.net") || h.Get("X-Amz-Cf-Id") != "":
		return "CloudFront"
	case hasSuffix(".akamai.net", ".akamaized.net"):
		return "Akamai"
	case hasSuffix(".fastly.net") || strings.Contains(strings.ToLower(h.Get("X-Served-By")), "cache-"):
		// WHY Contains (not Prefix) for x-served-by: edge POP names vary
		// ("cache-iad-kjyo" vs "cache-..."), only "cache-" is stable.
		return "Fastly"
	case hasSuffix(".sucuri.net") || h.Get("X-Sucuri-Id") != "":
		return "Sucuri"
	case hasSuffix(".incapsula.com") || h.Get("X-Iinfo") != "":
		return "Incapsula"
	case hasSuffix(".ddos-guard.net") || h.Get("X-Ddos-Guard") != "":
		return "DDoS-Guard"
	default:
		return "unknown"
	}
}
