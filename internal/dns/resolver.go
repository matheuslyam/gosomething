// Package dns resolves hostnames to IPs and CNAMEs behind a small interface
// so scans are testable with mocks instead of real network access.
package dns

import (
	"context"
	"net"
)

// Resolver abstracts name resolution for testability.
type Resolver interface {
	// LookupIPs returns all A/AAAA addresses for host.
	LookupIPs(ctx context.Context, host string) ([]net.IP, error)
	// LookupCNAME returns the canonical name for host ("" when none).
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// NetResolver is the production Resolver backed by the default resolver.
type NetResolver struct{}

// LookupIPs resolves via LookupIPAddr and converts []net.IPAddr to []net.IP.
// WHY LookupIPAddr instead of LookupIP: LookupIP requires a network argument
// ("ip", "ip4", "ip6") while LookupIPAddr takes only (ctx, host), which keeps
// our interface to a single host parameter.
func (NetResolver) LookupIPs(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// LookupCNAME resolves the canonical name via the default resolver.
func (NetResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return net.DefaultResolver.LookupCNAME(ctx, host)
}
