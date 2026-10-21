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
		reason string
	}{
		{"cloudflare cname", "x.cloudflare.net", http.Header{}, "Cloudflare", "cname suffix .cloudflare.net"},
		{"cloudflare header", "", header("Cf-Ray", "abc"), "Cloudflare", "header cf-ray"},
		{"cloudfront cname", "x.cloudfront.net", http.Header{}, "CloudFront", "cname suffix .cloudfront.net"},
		{"cloudfront header", "", header("X-Amz-Cf-Id", "abc"), "CloudFront", "header x-amz-cf-id"},
		{"akamai cname", "x.akamaized.net", http.Header{}, "Akamai", "cname suffix .akamaized.net"},
		{"akamai net", "x.akamai.net", http.Header{}, "Akamai", "cname suffix .akamai.net"},
		{"akamai false positive guard", "notakamai.com", http.Header{}, "unknown", "no signal"},
		{"fastly cname", "x.fastly.net", http.Header{}, "Fastly", "cname suffix .fastly.net"},
		{"fastly header", "", header("X-Served-By", "cache-iad-kjyo"), "Fastly", "header x-served-by"},
		{"served-by without cache falls through", "x.sucuri.net", header("X-Served-By", "web"), "Sucuri", "cname suffix .sucuri.net"},
		{"sucuri header", "", header("X-Sucuri-Id", "1"), "Sucuri", "header x-sucuri-id"},
		{"incapsula cname", "x.incapsula.com", http.Header{}, "Incapsula", "cname suffix .incapsula.com"},
		{"incapsula header", "", header("X-Iinfo", "1"), "Incapsula", "header x-iinfo"},
		{"ddos-guard cname", "x.ddos-guard.net", http.Header{}, "DDoS-Guard", "cname suffix .ddos-guard.net"},
		{"case insensitive cname", "X.CLOUDFLARE.NET.", http.Header{}, "Cloudflare", "cname suffix .cloudflare.net"},
		{"unknown empty", "", http.Header{}, "unknown", "no signal"},
		{"unknown random", "example.com", header("Server", "nginx"), "unknown", "no signal"},
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
