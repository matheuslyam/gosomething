package dns

import (
	"context"
	"net"
	"testing"
)

func TestOriginQueryV4(t *testing.T) {
	t.Parallel()

	got, err := OriginQuery(net.ParseIP("216.90.108.31"))
	if err != nil {
		t.Fatalf("OriginQuery error: %v", err)
	}
	// Fixture mirrors the documented Cymru example (verified 2026-10-21).
	if want := "31.108.90.216.origin.asn.cymru.com"; got != want {
		t.Errorf("OriginQuery = %q, want %q", got, want)
	}
}

func TestOriginQueryV6(t *testing.T) {
	t.Parallel()

	got, err := OriginQuery(net.ParseIP("2001:4860:b002::68"))
	if err != nil {
		t.Fatalf("OriginQuery error: %v", err)
	}
	// Prefix of the documented full form (verified 2026-10-21):
	// 8.6.0.0.0.0.0.0...2.origin6.asn.cymru.com.
	want := "8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.b.0.6.8.4.1.0.0.2.origin6.asn.cymru.com"
	if got != want {
		t.Errorf("OriginQuery = %q, want %q", got, want)
	}
}

func TestOriginQueryInvalid(t *testing.T) {
	t.Parallel()

	if _, err := OriginQuery(net.ParseIP("not-an-ip")); err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestParseOrigin(t *testing.T) {
	t.Parallel()

	// Byte-equal to the documented Cymru verbose line (verified 2026-10-21).
	recs, err := ParseOrigin("216.90.108.31", "23028 | 216.90.108.0/24 | US | arin | 1998-09-25")
	if err != nil {
		t.Fatalf("ParseOrigin error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("len = %d, want 1", len(recs))
	}
	r := recs[0]
	if r.ASN != 23028 || r.Prefix != "216.90.108.0/24" || r.CC != "US" || r.Registry != "arin" || r.Allocated != "1998-09-25" || r.IP != "216.90.108.31" {
		t.Errorf("unexpected record: %+v", r)
	}
	if r.Org != "unknown" {
		t.Errorf("Org = %q, want unknown before the asn-zone lookup", r.Org)
	}
}

func TestParseOriginMultihoming(t *testing.T) {
	t.Parallel()

	recs, err := ParseOrigin("10.0.0.1", "701 1239 | 10.0.0.0/24 | US | arin | 1992-11-10")
	if err != nil {
		t.Fatalf("ParseOrigin error: %v", err)
	}
	if len(recs) != 2 || recs[0].ASN != 701 || recs[1].ASN != 1239 {
		t.Errorf("multihoming must yield one record per ASN, got %+v", recs)
	}
}

func TestParseOriginBad(t *testing.T) {
	t.Parallel()

	for _, line := range []string{"", "23028 | only-two", "abc | 1.0.0.0/24 | US | arin | 2020-01-01", "0 | 1.0.0.0/24 | US | arin | 2020-01-01", "-7 | 1.0.0.0/24 | US | arin | 2020-01-01"} {
		if _, err := ParseOrigin("1.2.3.4", line); err == nil {
			t.Errorf("expected error for %q", line)
		}
	}
}

func TestParseASNName(t *testing.T) {
	t.Parallel()

	recs := []ASNRecord{{IP: "216.90.108.31", ASN: 23028, Org: "unknown"}}
	// Fixture mirrors the documented asn-zone line (verified 2026-10-21).
	ParseASNName("23028 | US | arin | 2002-01-04 | TEAM-CYMRU - Team Cymru Inc., US", recs)
	if recs[0].Org != "TEAM-CYMRU - Team Cymru Inc., US" {
		t.Errorf("Org = %q", recs[0].Org)
	}
}

func TestParseASNNameMismatchKeepsUnknown(t *testing.T) {
	t.Parallel()

	recs := []ASNRecord{{IP: "1.2.3.4", ASN: 1, Org: "unknown"}}
	ParseASNName("99999 | US | arin | 2002-01-04 | SOMEONE ELSE", recs)
	ParseASNName("garbage", recs)
	if recs[0].Org != "unknown" {
		t.Errorf("Org = %q, want unknown", recs[0].Org)
	}
}

func TestUnknownASN(t *testing.T) {
	t.Parallel()

	r := UnknownASN(net.ParseIP("127.0.0.1"))
	if r.IP != "127.0.0.1" || r.Org != "unknown" || r.ASN != 0 {
		t.Errorf("unexpected unknown record: %+v", r)
	}
}

// A canceled context fails fast without touching the network, keeping the
// error-path test deterministic offline (same pattern as LookupIPs/CNAME).
func TestNetResolverLookupASNCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (NetResolver{}).LookupASN(ctx, net.ParseIP("8.8.8.8")); err == nil {
		t.Error("expected error with canceled context")
	}
}
