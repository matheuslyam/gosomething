package dns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ASNRecord is one origin-ASN answer for an IP, enriched from Team Cymru's
// DNS zones (origin + asn). CC/Registry/Allocated are registry provenance
// (which RIR holds the record), never geolocation: anycast and multinational
// announcements make "CC as server location" false (verified 2026-10-21 in
// team-cymru.com/ip-asn-mapping).
type ASNRecord struct {
	IP        string `json:"ip"`
	ASN       int    `json:"asn"`
	Prefix    string `json:"prefix"`
	Org       string `json:"org"`
	CC        string `json:"cc"`
	Registry  string `json:"registry"`
	Allocated string `json:"allocated"`
}

// UnknownASN is the tolerated record when Cymru has no answer (NXDOMAIN,
// empty, unparsable): every resolved IP stays accounted for in Result.ASNs.
// WHY "unknown" org instead of omitting: a missing entry would silently
// shrink the per-IP mapping and look like fewer IPs were scanned.
func UnknownASN(ip net.IP) ASNRecord {
	return ASNRecord{IP: ip.String(), Org: "unknown"}
}

// OriginQuery returns the Cymru DNS name for ip: reversed octets plus
// origin.asn.cymru.com (v4), reversed nibbles plus origin6.asn.cymru.com
// (v6). Verified 2026-10-21: dig +short 31.108.90.216.origin.asn.cymru.com
// TXT → "23028 | 216.90.108.0/24 | US | arin | 1998-09-25".
func OriginQuery(ip net.IP) (string, error) {
	if v4 := ip.To4(); v4 != nil {
		// WHY To4 first: v4-mapped v6 addresses answer in the v4 zone.
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0]), nil
	}
	v16 := ip.To16()
	if v16 == nil {
		return "", fmt.Errorf("invalid IP %q", ip.String())
	}
	var sb strings.Builder
	for i := len(v16) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", v16[i]&0xf, v16[i]>>4)
	}
	sb.WriteString("origin6.asn.cymru.com")
	return sb.String(), nil
}

// ParseOrigin parses one origin-zone TXT line ("ASN | prefix | CC |
// registry | allocated"). An ASN field with several space-separated ASNs
// (multihoming) yields one ASNRecord per ASN sharing the remaining fields.
func ParseOrigin(ip string, line string) ([]ASNRecord, error) {
	parts := strings.SplitN(line, "|", 5)
	if len(parts) != 5 {
		return nil, fmt.Errorf("bad origin record %q", line)
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	tokens := strings.Fields(parts[0])
	if len(tokens) == 0 {
		return nil, fmt.Errorf("bad origin record %q", line)
	}
	out := make([]ASNRecord, 0, len(tokens))
	for _, tok := range tokens {
		n, err := strconv.Atoi(tok)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("bad origin record %q", line)
		}
		out = append(out, ASNRecord{
			IP: ip, ASN: n,
			Prefix:    parts[1],
			CC:        parts[2],
			Registry:  parts[3],
			Allocated: parts[4],
			Org:       "unknown",
		})
	}
	return out, nil
}

// ParseASNName folds one asn-zone TXT line ("ASN | CC | registry | allocated
// | AS Name") into recs, matching by ASN number. A name-query failure must
// not fail the record: Org stays "unknown" (name is decoration, origin data
// is the substance).
func ParseASNName(line string, recs []ASNRecord) {
	parts := strings.SplitN(line, "|", 5)
	if len(parts) != 5 {
		return
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return
	}
	for i := range recs {
		if recs[i].ASN == n && parts[4] != "" {
			recs[i].Org = parts[4]
		}
	}
}

// LookupASN resolves ip to its origin ASN records via Team Cymru DNS:
// origin zone for ASN+prefix, then one asn-zone query per distinct ASN for
// the org name. Any failure (NXDOMAIN, empty, unparsable) returns an error;
// callers tolerate it with UnknownASN (enrichment is best-effort, DNS-ok is
// what matters). Verified 2026-10-21: func (r *Resolver) LookupTXT(ctx
// context.Context, name string) ([]string, error) per pkg.go.dev/net.
func (NetResolver) LookupASN(ctx context.Context, ip net.IP) ([]ASNRecord, error) {
	// WHY ctx checked before any DNS: the cgo system resolver can complete
	// a lookup even on a canceled context, so without this the error path
	// would depend on resolver internals instead of failing fast offline.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	q, err := OriginQuery(ip)
	if err != nil {
		return nil, err
	}
	txts, err := net.DefaultResolver.LookupTXT(ctx, q)
	if err != nil {
		return nil, err
	}
	var recs []ASNRecord
	for _, t := range txts {
		parsed, err := ParseOrigin(ip.String(), t)
		if err != nil {
			return nil, err
		}
		recs = append(recs, parsed...)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("no ASN records for %s", ip.String())
	}
	// WHY name lookups sequential: usually a single ASN; parallelism here
	// would add goroutines for a second DNS round-trip nobody asked to go
	// fast (per-IP parallelism already lives in Scan).
	seen := map[int]bool{}
	for _, r := range recs {
		if seen[r.ASN] {
			continue
		}
		seen[r.ASN] = true
		nameQ := "AS" + strconv.Itoa(r.ASN) + ".asn.cymru.com"
		if names, err := net.DefaultResolver.LookupTXT(ctx, nameQ); err == nil {
			for _, n := range names {
				ParseASNName(n, recs)
			}
		}
	}
	return recs, nil
}
