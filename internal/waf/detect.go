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

// Detect returns the provider name plus the reason that fired, for verbose
// output. Reasons name the exact signal ("cname suffix .sucuri.net",
// "header x-sucuri-id") or "no signal".
//
// All CNAME matching is HasSuffix on the lowercased, dot-trimmed name (never
// Contains — "notakamai.com" must not match). Header lookup uses Get, which
// is already case-insensitive, so no manual lowering of keys.
// Verified 2026-10-20: func (h Header) Get(key string) string per
// https://pkg.go.dev/net/http#Header.Get (go1.27).
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
	// WHY sequential ifs (not else-if): a present-but-unmatched signal must
	// not block later checks (mirrors cdn.Detect).
	if s, ok := suffix(".cloudflare.net"); ok {
		return "Cloudflare", "cname suffix " + s
	}
	if k, ok := header("Cf-Ray", "Cf-Mitigated"); ok {
		return "Cloudflare", "header " + k
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "cloudflare") {
		// WHY Contains only for the Server value here: the token
		// "cloudflare" is distinctive (unlike generic "akamai"), and
		// Cloudflare documents Server: cloudflare on proxied responses.
		// Cf-Ray proves proxied edge; Cf-Mitigated proves a mitigation ran.
		return "Cloudflare", "server contains cloudflare"
	}
	if s, ok := suffix(".sucuri.net"); ok {
		return "Sucuri", "cname suffix " + s
	}
	if k, ok := header("X-Sucuri-Id", "X-Sucuri-Cache"); ok {
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
