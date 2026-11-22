package scan_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

// REQ-SCAN-022
func TestSecondServicePassIsTimeBoundedForSilentHosts(t *testing.T) {
	for _, n := range []int{1, 2, 6} {
		var ports []int
		for i := range n {
			ports = append(ports, 6000+i)
		}
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, ps []int, _ nmap.Options) ([]nmap.Host, error) {
			h := nmap.Host{Address: addrs[0], Up: true}
			for _, p := range ps {
				h.Ports = append(h.Ports, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: "unknown"})
			}
			return []nmap.Host{h}, nil
		}}
		settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: ports, MaxRate: 1000, Workers: 1}
		sc := &scan.Scanner{Store: &scantest.Store{}, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
		if err := sc.Run(context.Background(), testRun(settings)); err != nil {
			t.Fatal(err)
		}
		calls := servicesCalls(r)
		if len(calls) != 2 {
			t.Fatalf("%d ports: %d service detections, want the light pass and one second pass", n, len(calls))
		}
		second := calls[1]
		if !second.Opts.Standard || !slices.Equal(second.Ports, ports) {
			t.Fatalf("%d ports: second pass = %+v, want standard detection on %v", n, second, ports)
		}
		args, err := nmap.ServicesArgs(second.Addrs, second.Ports, second.Opts)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.Index(args, "--host-timeout")
		if i < 0 || i+1 >= len(args) {
			t.Fatalf("%d ports: second pass nmap args %q carry no --host-timeout, a host that accepts and never answers stalls the group", n, args)
		}
		bound, err := time.ParseDuration(args[i+1])
		if err != nil {
			t.Fatalf("%d ports: --host-timeout %q: %v", n, args[i+1], err)
		}
		lo, hi := time.Duration(n)*10*time.Second, min(time.Duration(n)*30*time.Second, 90*time.Second)
		if bound > 90*time.Second || bound < min(lo, 90*time.Second) || bound > hi {
			t.Errorf("%d ports: second pass --host-timeout %s, want about 20s per port, at most 90s", n, bound)
		}
		if !slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "--max-retries") }) {
			t.Errorf("%d ports: second pass nmap args %q carry no --max-retries, want a lower retry count", n, args)
		}
	}
}
