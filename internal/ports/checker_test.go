package ports

import (
	"context"
	"net"
	"testing"
	"time"
)

type stubDialer struct{ open bool }

func (s stubDialer) Open(context.Context, string) bool { return s.open }

func TestCheckAllOpen(t *testing.T) {
	t.Parallel()

	got := Check(context.Background(), "example.com", []int{80, 443}, stubDialer{open: true})
	if !got[80] || !got[443] {
		t.Errorf("expected all open, got %v", got)
	}
}

func TestCheckAllClosed(t *testing.T) {
	t.Parallel()

	got := Check(context.Background(), "example.com", []int{80, 443}, stubDialer{open: false})
	// WHY assert both keys: the schema must always carry 80 and 443, even
	// when closed, so JSON shape never depends on the outcome.
	if len(got) != 2 || got[80] || got[443] {
		t.Errorf("expected both closed, got %v", got)
	}
}

func TestNetDialerLocalhost(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no localhost listener available: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !(NetDialer{Timeout: 2 * time.Second}).Open(ctx, ln.Addr().String()) {
		t.Errorf("expected open for local listener %s", ln.Addr())
	}
	// WHY dynamic port, never 80/443: :0 picks a free port; binding 80/443
	// needs privileges and would make the test flaky.
	if (NetDialer{Timeout: 2 * time.Second}).Open(ctx, "127.0.0.1:1") {
		t.Error("expected closed for 127.0.0.1:1")
	}
}
