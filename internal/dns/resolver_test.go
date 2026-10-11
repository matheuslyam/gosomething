package dns

import (
	"context"
	"testing"
	"time"
)

// localhost resolves via the hosts file, so this test needs no network.
func TestNetResolverLocalhost(t *testing.T) {
	t.Parallel()

	ips, err := (NetResolver{}).LookupIPs(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("LookupIPs(localhost) error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one IP for localhost")
	}
	foundLoopback := false
	for _, ip := range ips {
		if ip.IsLoopback() {
			foundLoopback = true
		}
	}
	if !foundLoopback {
		t.Errorf("expected a loopback IP, got %v", ips)
	}
}

// A canceled context fails fast without touching the network, keeping the
// error-path test deterministic offline.
func TestNetResolverCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (NetResolver{}).LookupIPs(ctx, "localhost"); err == nil {
		t.Error("expected error with canceled context")
	}
	if _, err := (NetResolver{}).LookupCNAME(ctx, "localhost"); err == nil {
		t.Error("expected error with canceled context")
	}
}

func TestNetResolverTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := (NetResolver{}).LookupCNAME(ctx, "localhost"); err != nil {
		t.Logf("CNAME(localhost) error (tolerated, hosts-dependent): %v", err)
	}
}
