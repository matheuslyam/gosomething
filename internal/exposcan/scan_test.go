package exposcan

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/matheuslyam/gosomething/internal/dns"
	"github.com/matheuslyam/gosomething/internal/httpfetch"
)

type stubDNS struct {
	ips      []net.IP
	ipsErr   error
	cname    string
	cnameErr error
	asn      []dns.ASNRecord
	asnErr   error
}

func (s stubDNS) LookupIPs(context.Context, string) ([]net.IP, error) {
	return s.ips, s.ipsErr
}

func (s stubDNS) LookupCNAME(context.Context, string) (string, error) {
	return s.cname, s.cnameErr
}

func (s stubDNS) LookupASN(context.Context, net.IP) ([]dns.ASNRecord, error) {
	return s.asn, s.asnErr
}

type stubFetch struct {
	httpsRes httpfetch.HTTPResult
	httpsErr error
	httpRes  httpfetch.HTTPResult
	httpErr  error
}

func (s stubFetch) Fetch(_ context.Context, url string) (httpfetch.HTTPResult, error) {
	if strings.HasPrefix(url, "https://") {
		return s.httpsRes, s.httpsErr
	}
	return s.httpRes, s.httpErr
}

type stubDial struct{ open bool }

func (s stubDial) Open(context.Context, string) bool { return s.open }

func okHeader() http.Header {
	h := http.Header{}
	h.Set("Server", "nginx")
	h.Set("Strict-Transport-Security", "max-age=63072000")
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("Cf-Ray", "abc")
	return h
}

func okDeps() Deps {
	return Deps{
		DNS: stubDNS{
			ips:   []net.IP{net.ParseIP("93.184.216.34")},
			cname: "",
			asn: []dns.ASNRecord{{
				IP: "93.184.216.34", ASN: 15133,
				Prefix: "93.184.216.0/24", Org: "EDGECAST",
				CC: "US", Registry: "arin", Allocated: "1992-12-01",
			}},
		},
		HTTP: stubFetch{httpsRes: httpfetch.HTTPResult{
			Header:   okHeader(),
			Status:   200,
			FinalURL: "https://example.com",
		}},
		Dial: stubDial{open: true},
	}
}

func TestScanSuccess(t *testing.T) {
	t.Parallel()

	res, err := Scan(context.Background(), "example.com", "example.com", okDeps())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(res.IPs) != 1 || res.IPs[0] != "93.184.216.34" {
		t.Errorf("IPs = %v", res.IPs)
	}
	if res.CDN != "Cloudflare" {
		t.Errorf("CDN = %q, want Cloudflare (cf-ray)", res.CDN)
	}
	if res.WAF != "Cloudflare" {
		t.Errorf("WAF = %q, want Cloudflare (cf-ray edge)", res.WAF)
	}
	if len(res.ASNs) != 1 || res.ASNs[0].ASN != 15133 || res.ASNs[0].Org != "EDGECAST" {
		t.Errorf("ASNs = %+v, want the stubbed EDGECAST record", res.ASNs)
	}
	if res.Reasons["cdn"] != "header cf-ray" {
		t.Errorf("reasons[cdn] = %q, want header cf-ray", res.Reasons["cdn"])
	}
	if res.Reasons["waf"] != "header cf-ray" {
		t.Errorf("reasons[waf] = %q, want header cf-ray", res.Reasons["waf"])
	}
	if res.Reasons["hsts"] != "strict-transport-security present (https)" {
		t.Errorf("reasons[hsts] = %q", res.Reasons["hsts"])
	}
	if res.Reasons["csp"] != "content-security-policy present (https)" {
		t.Errorf("reasons[csp] = %q", res.Reasons["csp"])
	}
	if res.Reasons["server"] != "server|x-powered-by present" {
		t.Errorf("reasons[server] = %q", res.Reasons["server"])
	}
	if !res.HSTS || !res.CSP || !res.ServerPresent {
		t.Errorf("flags HSTS/CSP/ServerPresent = %v/%v/%v", res.HSTS, res.CSP, res.ServerPresent)
	}
	if res.Headers["server"] != "nginx" {
		t.Errorf("server header = %q", res.Headers["server"])
	}
	if !res.Ports[80] || !res.Ports[443] {
		t.Errorf("ports = %v, want both open", res.Ports)
	}
	if res.HTTPError != "" {
		t.Errorf("HTTPError = %q, want empty on success", res.HTTPError)
	}
}

func TestScanDNSFail(t *testing.T) {
	t.Parallel()

	deps := okDeps()
	deps.DNS = stubDNS{ipsErr: errors.New("no such host")}
	if _, err := Scan(context.Background(), "example.com", "example.com", deps); err == nil {
		t.Error("expected error on DNS failure")
	}
}

func TestScanCNAMEFailureTolerated(t *testing.T) {
	t.Parallel()

	deps := okDeps()
	deps.DNS = stubDNS{ips: []net.IP{net.ParseIP("93.184.216.34")}, cnameErr: errors.New("no cname")}
	res, err := Scan(context.Background(), "example.com", "example.com", deps)
	if err != nil {
		t.Fatalf("CNAME failure must be tolerated, got: %v", err)
	}
	if res.CNAME != "" {
		t.Errorf("CNAME = %q, want empty", res.CNAME)
	}
}

func TestScanHTTPFallbackPreservesFirstError(t *testing.T) {
	t.Parallel()

	deps := okDeps()
	deps.HTTP = stubFetch{
		httpsErr: context.DeadlineExceeded,
		httpRes: httpfetch.HTTPResult{
			Header:   http.Header{},
			Status:   200,
			FinalURL: "http://example.com",
		},
	}
	res, err := Scan(context.Background(), "example.com", "example.com", deps)
	if err != nil {
		t.Fatalf("fallback success must not error, got: %v", err)
	}
	if !strings.Contains(res.HTTPError, "https:") {
		t.Errorf("HTTPError must preserve first error, got %q", res.HTTPError)
	}
	if res.HSTS || res.CSP {
		t.Error("HSTS/CSP must stay false on http fallback")
	}
}

func TestScanHTTPFailKeepsPartial(t *testing.T) {
	t.Parallel()

	deps := okDeps()
	deps.HTTP = stubFetch{httpsErr: errors.New("boom"), httpErr: errors.New("boom")}
	res, err := Scan(context.Background(), "example.com", "example.com", deps)
	if err != nil {
		t.Fatalf("HTTP failure must not abort with DNS ok, got: %v", err)
	}
	if len(res.IPs) != 1 {
		t.Errorf("partial IPs lost: %v", res.IPs)
	}
	if res.HTTPError == "" {
		t.Error("expected HTTPError warning")
	}
}

func TestScanHeadersAllowlist(t *testing.T) {
	t.Parallel()

	h := okHeader()
	h.Set("Set-Cookie", "session=secret")
	h.Set("X-Custom", "nope")
	deps := okDeps()
	deps.HTTP = stubFetch{httpsRes: httpfetch.HTTPResult{Header: h, Status: 200, FinalURL: "https://example.com"}}
	res, err := Scan(context.Background(), "example.com", "example.com", deps)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if !res.HasSetCookie {
		t.Error("expected HasSetCookie")
	}
	if _, ok := res.Headers["set-cookie"]; ok {
		t.Error("cookie value must never enter Headers")
	}
	for _, v := range res.Headers {
		if strings.Contains(v, "secret") {
			t.Errorf("secret leaked into headers: %v", res.Headers)
		}
	}
	if _, ok := res.Headers["x-custom"]; ok {
		t.Errorf("non-allowlisted header kept: %v", res.Headers)
	}
}

func TestScanCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := okDeps()
	deps.DNS = stubDNS{ipsErr: ctx.Err()}
	if _, err := Scan(ctx, "example.com", "example.com", deps); err == nil {
		t.Error("expected error with canceled context")
	}
}

func TestScanWAFUnknownByDefault(t *testing.T) {
	t.Parallel()

	deps := okDeps()
	deps.HTTP = stubFetch{httpsRes: httpfetch.HTTPResult{
		Header:   http.Header{},
		Status:   200,
		FinalURL: "https://example.com",
	}}
	res, err := Scan(context.Background(), "example.com", "example.com", deps)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if res.WAF != "unknown" {
		t.Errorf("WAF = %q, want unknown without edge signals", res.WAF)
	}
}

func TestScanASNUnknownTolerated(t *testing.T) {
	t.Parallel()

	// WHY tolerated like CNAME: enrichment is best-effort; the IP set
	// below is what matters. Every IP stays accounted for via UnknownASN.
	deps := okDeps()
	deps.DNS = stubDNS{ips: []net.IP{net.ParseIP("93.184.216.34")}, asnErr: errors.New("NXDOMAIN")}
	res, err := Scan(context.Background(), "example.com", "example.com", deps)
	if err != nil {
		t.Fatalf("ASN failure must not abort with DNS ok, got: %v", err)
	}
	if len(res.ASNs) != 1 || res.ASNs[0].Org != "unknown" || res.ASNs[0].IP != "93.184.216.34" {
		t.Errorf("ASNs = %+v, want one unknown record for the IP", res.ASNs)
	}
}

func TestScanASNMultihoming(t *testing.T) {
	t.Parallel()

	deps := okDeps()
	deps.DNS = stubDNS{
		ips: []net.IP{net.ParseIP("10.0.0.1")},
		asn: []dns.ASNRecord{
			{IP: "10.0.0.1", ASN: 701, Org: "UUNET"},
			{IP: "10.0.0.1", ASN: 1239, Org: "SPRINT"},
		},
	}
	res, err := Scan(context.Background(), "example.com", "example.com", deps)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(res.ASNs) != 2 || res.ASNs[0].ASN != 701 || res.ASNs[1].ASN != 1239 {
		t.Errorf("ASNs = %+v, want both origins in order", res.ASNs)
	}
}

func TestScanCookiesCapturedRaw(t *testing.T) {
	t.Parallel()

	// WHY raw here: Scan owns collection, presentation owns redaction;
	// masking happens at render (--show-cookies decides at the edge).
	h := okHeader()
	h.Set("Set-Cookie", "session=AbCdEfGh1234; Path=/; Secure; HttpOnly")
	deps := okDeps()
	deps.HTTP = stubFetch{httpsRes: httpfetch.HTTPResult{Header: h, Status: 200, FinalURL: "https://example.com"}}
	res, err := Scan(context.Background(), "example.com", "example.com", deps)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if !res.HasSetCookie {
		t.Error("expected HasSetCookie")
	}
	if len(res.Cookies) != 1 || res.Cookies[0] != "session=AbCdEfGh1234; Path=/; Secure; HttpOnly" {
		t.Errorf("Cookies = %v, want the raw value", res.Cookies)
	}
	if _, ok := res.Headers["set-cookie"]; ok {
		t.Error("cookie value must never enter Headers")
	}
}

func TestScanHTTPFailReasonsDeterministic(t *testing.T) {
	t.Parallel()

	// WHY explicit asserts: Reasons keys must be identical on the fail path
	// so verbose output and JSON never depend on which path ran.
	deps := okDeps()
	deps.HTTP = stubFetch{httpsErr: errors.New("boom"), httpErr: errors.New("boom")}
	res, err := Scan(context.Background(), "example.com", "example.com", deps)
	if err != nil {
		t.Fatalf("HTTP failure must not abort with DNS ok, got: %v", err)
	}
	for k, want := range map[string]string{
		"cdn": "no signal", "waf": "no signal",
		"hsts": "not evaluated (no fetch)", "csp": "not evaluated (no fetch)",
		"server": "absent",
	} {
		if res.Reasons[k] != want {
			t.Errorf("Reasons[%q] = %q, want %q", k, res.Reasons[k], want)
		}
	}
}

// The JSON shape must be stable: exact keys, initialized collections.
func TestResultJSONTags(t *testing.T) {
	t.Parallel()

	res, err := Scan(context.Background(), "example.com", "example.com", okDeps())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	raw, _ := json.Marshal(res)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"domain", "punycode", "ips", "cname", "cdn", "waf", "asns", "cookies", "reasons", "ports", "headers", "hsts", "csp", "hasSetCookie", "serverPresent", "httpStatus", "finalUrl"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing JSON key %q in %s", k, raw)
		}
	}
}
