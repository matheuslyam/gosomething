package cdn

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
		{"cloudfront cname", "x.cloudfront.net", http.Header{}, "CloudFront"},
		{"cloudfront header", "", header("X-Amz-Cf-Id", "abc"), "CloudFront"},
		{"akamai cname", "x.akamaized.net", http.Header{}, "Akamai"},
		{"akamai net", "x.akamai.net", http.Header{}, "Akamai"},
		{"akamai false positive guard", "notakamai.com", http.Header{}, "unknown"},
		{"fastly cname", "x.fastly.net", http.Header{}, "Fastly"},
		{"fastly header", "", header("X-Served-By", "cache-iad-kjyo"), "Fastly"},
		{"sucuri cname", "x.sucuri.net", http.Header{}, "Sucuri"},
		{"sucuri header", "", header("X-Sucuri-Id", "1"), "Sucuri"},
		{"incapsula cname", "x.incapsula.com", http.Header{}, "Incapsula"},
		{"incapsula header", "", header("X-Iinfo", "1"), "Incapsula"},
		{"ddos-guard cname", "x.ddos-guard.net", http.Header{}, "DDoS-Guard"},
		{"case insensitive cname", "X.CLOUDFLARE.NET.", http.Header{}, "Cloudflare"},
		{"unknown empty", "", http.Header{}, "unknown"},
		{"unknown random", "example.com", header("Server", "nginx"), "unknown"},
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
