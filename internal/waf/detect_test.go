package waf

import (
	"net/http"
	"testing"
)

func TestDetect(t *testing.T) {
	t.Parallel()

	header := func(k, v string) http.Header {
		h := http.Header{}
		h.Set(k, v)
		return h
	}

	tests := []struct {
		name   string
		cname  string
		header http.Header
		want   string
		reason string
	}{
		{"cloudflare cname", "x.cloudflare.net", http.Header{}, "Cloudflare", "cname suffix .cloudflare.net"},
		{"cloudflare header", "", header("Cf-Ray", "abc"), "Cloudflare", "header cf-ray"},
		{"cloudflare mitigated", "", header("Cf-Mitigated", "challenge"), "Cloudflare", "header cf-mitigated"},
		{"cloudflare server", "", header("Server", "cloudflare"), "Cloudflare", "server contains cloudflare"},
		{"sucuri cname", "x.sucuri.net", http.Header{}, "Sucuri", "cname suffix .sucuri.net"},
		{"sucuri header id", "", header("X-Sucuri-Id", "1"), "Sucuri", "header x-sucuri-id"},
		{"sucuri header cache", "", header("X-Sucuri-Cache", "HIT"), "Sucuri", "header x-sucuri-cache"},
		{"incapsula cname", "x.incapsula.com", http.Header{}, "Incapsula", "cname suffix .incapsula.com"},
		{"incapsula header", "", header("X-Iinfo", "1"), "Incapsula", "header x-iinfo"},
		{"ddos-guard cname", "x.ddos-guard.net", http.Header{}, "DDoS-Guard", "cname suffix .ddos-guard.net"},
		{"ddos-guard header", "", header("X-Ddos-Guard", "1"), "DDoS-Guard", "header x-ddos-guard"},
		{"case insensitive cname", "X.CLOUDFLARE.NET.", http.Header{}, "Cloudflare", "cname suffix .cloudflare.net"},
		{"false positive guard", "notcloudflare.com", http.Header{}, "unknown", "no signal"},
		{"unknown empty", "", http.Header{}, "unknown", "no signal"},
		{"unknown random", "example.com", header("Server", "nginx"), "unknown", "no signal"},
		{"nil header safe", "example.com", nil, "unknown", "no signal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, reason := Detect(tt.cname, tt.header)
			if got != tt.want {
				t.Errorf("Detect(%q) = %q, want %q", tt.cname, got, tt.want)
			}
			if reason != tt.reason {
				t.Errorf("Detect(%q) reason = %q, want %q", tt.cname, reason, tt.reason)
			}
		})
	}
}
