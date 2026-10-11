// Package ports checks TCP port reachability behind a small interface so
// scans stay testable without real network access.
package ports

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

// Dialer abstracts a single TCP open-or-not probe.
type Dialer interface {
	// Open reports whether hostport accepts a TCP connection.
	Open(ctx context.Context, hostport string) bool
}

// NetDialer is the production Dialer.
type NetDialer struct {
	// Timeout caps each dial; it must already be min(5s, global).
	Timeout time.Duration
}

// Open dials and closes immediately.
// WHY bool instead of (bool, error): v1 favors a didactic signal over the
// failure reason; the error detail returns in a future verbose mode. The
// connection is always closed to avoid leaking file descriptors.
func (d NetDialer) Open(ctx context.Context, hostport string) bool {
	dialer := net.Dialer{Timeout: d.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Check probes every port on host in parallel under ctx.
// WHY parallel with WaitGroup: 80+443 sequential doubles worst-case latency;
// the shared ctx still bounds the total. The result always contains every
// requested port (false when closed) for a stable JSON schema.
func Check(ctx context.Context, host string, ports []int, d Dialer) map[int]bool {
	out := make(map[int]bool, len(ports))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			open := d.Open(ctx, net.JoinHostPort(host, strconv.Itoa(port)))
			mu.Lock()
			out[port] = open
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return out
}
