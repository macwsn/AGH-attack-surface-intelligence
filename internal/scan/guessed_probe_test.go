package scan_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

type bubbleClock struct{}

func (bubbleClock) Now() time.Time                         { return time.Now() }
func (bubbleClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// REQ-SCAN-018 REQ-SCAN-019
func TestHangingUnidentifiedPortsKeepRateAndPauseNoHost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		guessed := []int{7001, 7002, 7003}
		web := []int{8001, 8002, 8003, 8004, 8005, 8006, 8007}
		isGuessed := map[int]bool{}
		for _, p := range guessed {
			isGuessed[p] = true
		}
		var (
			mu    sync.Mutex
			holds []time.Duration
		)
		tr := &scantest.Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ps, _ := net.SplitHostPort(scantest.Target(r))
			if p, _ := strconv.Atoi(ps); isGuessed[p] {
				start := time.Now()
				<-r.Context().Done()
				mu.Lock()
				holds = append(holds, time.Since(start))
				mu.Unlock()
				return
			}
			fmt.Fprint(w, "<title>ok</title>")
		})}
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
			hosts := make([]nmap.Host, len(addrs))
			for i, a := range addrs {
				hosts[i] = nmap.Host{Address: a, Up: true}
				for _, p := range guessed {
					hosts[i].Ports = append(hosts[i].Ports, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: "unknown"})
				}
				for _, p := range web {
					hosts[i].Ports = append(hosts[i].Ports, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: "http"})
				}
			}
			return hosts, nil
		}}
		st := &scantest.Store{}
		settings := inventory.RunSettings{Targets: []string{"10.9.0.0/27"}, Ports: append(append([]int{}, guessed...), web...),
			MaxRate: 1000, Workers: 1, GroupSize: 16}
		sc := &scan.Scanner{Store: st, Runner: r, Clock: bubbleClock{}, Transport: tr.For}
		if err := sc.Run(context.Background(), testRun(settings)); err != nil {
			t.Fatal(err)
		}

		mu.Lock()
		for _, d := range holds {
			if d > 3*time.Second {
				t.Errorf("probe of an unidentified port held for %s, want a short timeout of at most 3s", d)
				break
			}
		}
		mu.Unlock()

		for _, s := range st.RateSamples() {
			if s.Effective != s.Configured {
				t.Errorf("sample %+v: effective limit lowered to %d of %d by timeouts on unidentified ports, want the rate kept", s, s.Effective, s.Configured)
			}
		}

		hosts := st.Hosts()
		if len(hosts) == 0 {
			t.Fatal("no hosts recorded")
		}
		paused := 0
		for _, h := range hosts {
			for _, s := range h.Services {
				if isGuessed[s.Port] {
					continue
				}
				if s.HTTP == nil || s.HTTP.StatusCode != http.StatusOK {
					paused++
					break
				}
			}
		}
		if paused > 0 {
			t.Errorf("%d of %d hosts paused by timeouts on unidentified ports, want none paused", paused, len(hosts))
		}
		if late := st.Late(); len(late) != 0 {
			t.Errorf("re-probe = %+v, want none", late)
		}
	})
}
