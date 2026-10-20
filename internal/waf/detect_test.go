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
	}{
		{"cloudflare cname", "x.cloudflare.net", http.Header{}, "Cloudflare"},
		{"cloudflare header", "", header("Cf-Ray", "abc"), "Cloudflare"},
		{"cloudflare mitigated", "", header("Cf-Mitigated", "challenge"), "Cloudflare"},
		{"cloudflare server", "", header("Server", "cloudflare"), "Cloudflare"},
		{"sucuri cname", "x.sucuri.net", http.Header{}, "Sucuri"},
		{"sucuri header id", "", header("X-Sucuri-Id", "1"), "Sucuri"},
		{"sucuri header cache", "", header("X-Sucuri-Cache", "HIT"), "Sucuri"},
		{"incapsula cname", "x.incapsula.com", http.Header{}, "Incapsula"},
		{"incapsula header", "", header("X-Iinfo", "1"), "Incapsula"},
		{"ddos-guard cname", "x.ddos-guard.net", http.Header{}, "DDoS-Guard"},
		{"ddos-guard header", "", header("X-Ddos-Guard", "1"), "DDoS-Guard"},
		{"case insensitive cname", "X.CLOUDFLARE.NET.", http.Header{}, "Cloudflare"},
		{"false positive guard", "notcloudflare.com", http.Header{}, "unknown"},
		{"unknown empty", "", http.Header{}, "unknown"},
		{"unknown random", "example.com", header("Server", "nginx"), "unknown"},
		{"nil header safe", "example.com", nil, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Detect(tt.cname, tt.header); got != tt.want {
				t.Errorf("Detect(%q) = %q, want %q", tt.cname, got, tt.want)
			}
		})
	}
}
