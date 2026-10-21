package exposcan

import "strings"

// MaskCookieValue redacts the value of one raw Set-Cookie string, keeping
// the name and attributes intact: the attributes (Secure, HttpOnly,
// SameSite, Path, Domain, Max-Age) are the audit signal, the value is the
// secret. Mirrors secrets.Mask: first4+…+last4, values under 8 chars become
// "****". A chunk without "=" is returned as-is (malformed, nothing to
// split).
func MaskCookieValue(raw string) string {
	pair, attrs := raw, ""
	if i := strings.Index(raw, ";"); i >= 0 {
		pair, attrs = raw[:i], raw[i:]
	}
	name, value := pair, ""
	if i := strings.Index(pair, "="); i >= 0 {
		name, value = pair[:i], pair[i+1:]
	} else {
		return raw
	}
	masked := "****"
	if len(value) >= 8 {
		masked = value[:4] + "…" + value[len(value)-4:]
	}
	return name + "=" + masked + attrs
}

// MaskCookies applies MaskCookieValue to every raw cookie.
func MaskCookies(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		out = append(out, MaskCookieValue(c))
	}
	return out
}
