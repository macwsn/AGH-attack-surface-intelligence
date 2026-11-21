package scan_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

// REQ-SCAN-002
func TestMaxRateCapsNmapAndProbeTogether(t *testing.T) {
	for _, tc := range []struct{ workers, maxRate int }{
		{workers: 1, maxRate: 20},
		{workers: 4, maxRate: 20},
		{workers: 16, maxRate: 10},
	} {
		t.Run(fmt.Sprintf("workers=%d,max-rate=%d", tc.workers, tc.maxRate), func(t *testing.T) {
			var (
				mu   sync.Mutex
				sum  int
				peak int
			)
			track := func(opts nmap.Options) func() {
				mu.Lock()
				defer mu.Unlock()
				if opts.MaxRate < 1 {
					t.Errorf("nmap call MaxRate = %d, want >= 1 (0 means unlimited)", opts.MaxRate)
				}
				sum += opts.MaxRate
				peak = max(peak, sum)
				return func() {
					mu.Lock()
					sum -= opts.MaxRate
					mu.Unlock()
				}
			}
			r := &nmaptest.Runner{
				DiscoverFunc: func(ctx context.Context, addrs []string, opts nmap.Options) ([]nmap.Host, error) {
					defer track(opts)()
					time.Sleep(3 * time.Millisecond)
					return allUp(ctx, addrs, opts)
				},
				ServicesFunc: func(ctx context.Context, addrs []string, ports []int, opts nmap.Options) ([]nmap.Host, error) {
					defer track(opts)()
					time.Sleep(3 * time.Millisecond)
					return openPorts(80)(ctx, addrs, ports, opts)
				},
			}
			start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			clock := scantest.NewClock(start)
			tr := &scantest.Transport{Clock: clock, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, "<title>ok</title>")
			})}
			settings := inventory.RunSettings{Targets: []string{"10.9.0.0/25"}, Ports: []int{80}, MaxRate: tc.maxRate, Workers: tc.workers, GroupSize: 4}
			s := &scan.Scanner{Store: &scantest.Store{}, Runner: r, Clock: clock, Transport: tr.For}
			if err := s.Run(context.Background(), testRun(settings)); err != nil {
				t.Fatalf("Run: %v", err)
			}
			reqs := tr.Requests()
			if len(reqs) < 2*tc.maxRate {
				t.Fatalf("probe requests = %d, want at least %d to measure the probe rate", len(reqs), 2*tc.maxRate)
			}
			first, last := reqs[0].Time, reqs[0].Time
			for _, q := range reqs {
				if q.Time.Before(first) {
					first = q.Time
				}
				if q.Time.After(last) {
					last = q.Time
				}
			}
			probeRate := float64(len(reqs)) / (last.Sub(first).Seconds() + 1)
			if float64(peak)+probeRate > float64(tc.maxRate) {
				t.Fatalf("nmap max-rate sum %d + probe %.1f req/s exceeds --max-rate %d", peak, probeRate, tc.maxRate)
			}
		})
	}
}
