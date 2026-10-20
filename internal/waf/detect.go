// Package waf heuristically identifies edge WAF providers from a CNAME and
// HTTP response headers. Detection is best-effort and passive: a match proves
// traffic went through the provider edge (where WAF can be enabled), never
// that a blocking rule is active. Anything without a known signal returns
// "unknown" (never "none" — absence of a signal is not proof of absence).
//
// Privacy: only header presence is inspected, never cookie values. Set-Cookie
// is not read here at all.
package waf

import (
	"net/http"
	"strings"
)

// Detect returns the provider name or "unknown".
//
// All CNAME matching is HasSuffix on the lowercased, dot-trimmed name (never
// Contains — "notakamai.com" must not match). Header lookup uses Get, which
// is already case-insensitive, so no manual lowering of keys.
// Verified 2026-10-20: func (h Header) Get(key string) string per
// https://pkg.go.dev/net/http#Header.Get (go1.27).
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
	case hasSuffix(".cloudflare.net") || h.Get("Cf-Ray") != "" || h.Get("Cf-Mitigated") != "" ||
		strings.Contains(strings.ToLower(h.Get("Server")), "cloudflare"):
		// WHY Contains only for the Server value here: the token
		// "cloudflare" is distinctive (unlike generic "akamai"), and
		// Cloudflare documents Server: cloudflare on proxied responses.
		// Cf-Ray proves proxied edge; Cf-Mitigated proves a mitigation ran.
		return "Cloudflare"
	case hasSuffix(".sucuri.net") || h.Get("X-Sucuri-Id") != "" || h.Get("X-Sucuri-Cache") != "":
		return "Sucuri"
	case hasSuffix(".incapsula.com") || h.Get("X-Iinfo") != "":
		return "Incapsula"
	case hasSuffix(".ddos-guard.net") || h.Get("X-Ddos-Guard") != "":
		return "DDoS-Guard"
	default:
		return "unknown"
	}
}
