package scan_test

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// REQ-SCAN-018 REQ-SCAN-019: unidentified ports that accept and then time out, over several minutes and many
// adaptive intervals, neither lower the run's rate nor pause a host.
func TestLongRunWithTimingOutUnidentifiedPortsKeepsRate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		guessed := map[int]bool{7001: true, 7002: true, 7003: true}
		web := []int{8001, 8002, 8003, 8004, 8005, 8006, 8007}
		inner := &scantest.Transport{}
		start := time.Now()
		transport := func(target string) http.RoundTripper {
			next := inner.For(target)
			_, ps, _ := net.SplitHostPort(target)
			port, _ := strconv.Atoi(ps)
			return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				if guessed[port] {
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				return next.RoundTrip(r)
			})
		}
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
			hosts := make([]nmap.Host, len(addrs))
			for i, a := range addrs {
				hosts[i] = nmap.Host{Address: a, Up: true}
				for p := range guessed {
					hosts[i].Ports = append(hosts[i].Ports, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: "unknown"})
				}
				for _, p := range web {
					hosts[i].Ports = append(hosts[i].Ports, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: "http"})
				}
			}
			return hosts, nil
		}}
		st := &scantest.Store{}
		settings := inventory.RunSettings{Targets: []string{"10.9.0.0/24"}, Ports: []int{7001, 7002, 7003, 8001, 8002, 8003, 8004, 8005, 8006, 8007},
			MaxRate: 1000, Workers: 1, GroupSize: 64}
		if err := (&scan.Scanner{Store: st, Runner: r, Clock: bubbleClock{}, Transport: transport}).Run(context.Background(), testRun(settings)); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d < 3*time.Minute {
			t.Fatalf("run took %s of fake time, want several minutes so the controller gets many windows", d)
		}
		samples := st.RateSamples()
		if len(samples) < 3 {
			t.Fatalf("samples = %+v, want several minutes", samples)
		}
		for _, s := range samples {
			if s.Effective != s.Configured {
				t.Errorf("sample %+v: effective limit lowered by timeouts on unidentified ports", s)
			}
		}
		for _, h := range st.Hosts() {
			for _, s := range h.Services {
				if !guessed[s.Port] && (s.HTTP == nil || s.HTTP.StatusCode != http.StatusOK) {
					t.Errorf("%s:%d = %+v, want 200 (host paused by unidentified ports?)", h.Address, s.Port, s.HTTP)
				}
			}
		}
	})
}
