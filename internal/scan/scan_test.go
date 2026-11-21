package scan_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asi/internal/detect"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
	"asi/internal/targets"
)

func testRun(settings inventory.RunSettings) inventory.Run {
	return inventory.Run{ID: 1, Name: "t", InactiveAfter: 3, Status: inventory.RunRunning, Settings: settings}
}

func expand(t *testing.T, include, exclude []string) []string {
	t.Helper()
	in, err := targets.Parse(strings.NewReader(strings.Join(include, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	ex, err := targets.Parse(strings.NewReader(strings.Join(exclude, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	set, err := targets.Build(context.Background(), in, ex, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for tg := range set.All() {
		out = append(out, tg.Addr.String())
	}
	return out
}

func allUp(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
	hosts := make([]nmap.Host, len(addrs))
	for i, a := range addrs {
		hosts[i] = nmap.Host{Address: a, Up: true}
	}
	return hosts, nil
}

func openPorts(ports ...int) func(context.Context, []string, []int, nmap.Options) ([]nmap.Host, error) {
	return func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
		hosts := make([]nmap.Host, len(addrs))
		for i, a := range addrs {
			hosts[i] = nmap.Host{Address: a, Up: true}
			for _, p := range ports {
				hosts[i].Ports = append(hosts[i].Ports, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: "http"})
			}
		}
		return hosts, nil
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// REQ-SCAN-001
func TestWorkerPool(t *testing.T) {
	for _, tc := range []struct {
		workers int
		block   bool
	}{
		{workers: 3, block: true},
		{workers: 1, block: false},
	} {
		t.Run(fmt.Sprintf("workers=%d", tc.workers), func(t *testing.T) {
			var (
				mu       sync.Mutex
				inFlight int
				peak     int
			)
			release := make(chan struct{})
			if !tc.block {
				close(release)
			}
			r := &nmaptest.Runner{DiscoverFunc: func(ctx context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
				mu.Lock()
				inFlight++
				peak = max(peak, inFlight)
				mu.Unlock()
				defer func() {
					mu.Lock()
					inFlight--
					mu.Unlock()
				}()
				time.Sleep(2 * time.Millisecond)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return []nmap.Host{{Address: addrs[0], Up: true}}, nil
			}}
			st := &scantest.Store{}
			include, exclude := []string{"10.0.0.0/25"}, []string{"10.0.0.7", "10.0.0.40-45"}
			settings := inventory.RunSettings{Targets: include, Excludes: exclude, Ports: []int{80}, MaxRate: 100, Workers: tc.workers, GroupSize: 12}
			s := &scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{}).For}
			done := make(chan error, 1)
			go func() { done <- s.Run(context.Background(), testRun(settings)) }()
			if tc.block {
				waitFor(t, "3 groups in flight", func() bool {
					mu.Lock()
					defer mu.Unlock()
					return inFlight == 3
				})
				time.Sleep(50 * time.Millisecond)
				close(release)
			}
			if err := <-done; err != nil {
				t.Fatalf("Run: %v", err)
			}
			if peak != tc.workers {
				t.Fatalf("peak groups in flight = %d, want %d", peak, tc.workers)
			}
			want := expand(t, include, exclude)
			groups := st.Groups()
			if len(groups) != 10 {
				t.Fatalf("groups = %d, want 10 (%d addresses / 12)", len(groups), len(want))
			}
			var got []string
			seen := map[string]int{}
			for i, g := range groups {
				if g.Index != i {
					t.Fatalf("group %d has index %d", i, g.Index)
				}
				for _, a := range g.Addresses {
					seen[a]++
					got = append(got, a)
				}
				if len(g.Hosts) != 1 || g.Hosts[0].Address != g.Addresses[0] {
					t.Fatalf("group %d hosts = %+v", g.Index, g.Hosts)
				}
			}
			for a, n := range seen {
				if n != 1 {
					t.Fatalf("address %s is in %d groups", a, n)
				}
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("union of group addresses differs from the target set:\n got %v\nwant %v", got, want)
			}
			if s := st.Statuses(); len(s) != 1 || s[0] != inventory.RunCompleted {
				t.Fatalf("statuses = %v, want [completed]", s)
			}
		})
	}
}

// REQ-SCAN-002
func TestRateLimitLimiter(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := scantest.NewClock(start)
	l := scan.NewLimiter(10, clock)
	for range 100 {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := clock.Now().Sub(start); d < 9*time.Second {
		t.Fatalf("100 tokens at 10/s took %s of fake time, want >= 9s", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait on cancelled context = %v", err)
	}
}

func writeSignatures(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sigs := `
- id: sig-a
  name: A
  kind: technology
  category: test
  confidence: 50
  request: { method: GET, path: /a }
  match:
    all:
      - { type: body_regex, value: 'page-a' }
- id: sig-b
  name: B
  kind: admin-panel
  category: test
  confidence: 50
  request: { method: GET, path: /b }
  match:
    all:
      - { type: body_regex, value: 'page-b' }
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(sigs), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// REQ-SCAN-002
func TestRateLimit(t *testing.T) {
	wall := time.Now()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := scantest.NewClock(start)
	tr := &scantest.Transport{Clock: clock, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/home", http.StatusFound)
		case "/home":
			fmt.Fprint(w, "<title>home</title>")
		case "/a":
			fmt.Fprint(w, "page-a")
		case "/b":
			fmt.Fprint(w, "page-b")
		default:
			http.NotFound(w, r)
		}
	})}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
	settings := inventory.RunSettings{
		Targets: []string{"10.1.0.1-20"}, Ports: []int{80}, MaxRate: 10, Workers: 1, SignaturesDir: writeSignatures(t),
	}
	st := &scantest.Store{}
	s := &scan.Scanner{Store: st, Runner: r, Clock: clock, Transport: tr.For}
	if err := s.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	reqs := tr.Requests()
	if len(reqs) != 100 {
		t.Fatalf("requests = %d, want 100 (20 hosts x root, redirect, favicon, 2 signature paths)", len(reqs))
	}
	if d := clock.Now().Sub(start); d < 9*time.Second {
		t.Fatalf("100 requests at MaxRate 10 advanced the fake clock by %s, want >= 9s", d)
	}
	for _, a := range reqs {
		n := 0
		for _, b := range reqs {
			if !b.Time.Before(a.Time) && b.Time.Before(a.Time.Add(time.Second)) {
				n++
			}
		}
		if n > 20 {
			t.Fatalf("%d requests in the 1s window starting at %s, want <= 20", n, a.Time.Sub(start))
		}
	}
	for _, h := range st.Hosts() {
		if len(h.Services) != 1 || h.Services[0].HTTP == nil || len(h.Services[0].Findings) != 2 {
			t.Fatalf("host %s services = %+v, want one probed service with 2 findings", h.Address, h.Services)
		}
	}
	if el := time.Since(wall); el > 5*time.Second {
		t.Fatalf("test took %s of wall time", el)
	}
}

// REQ-SCAN-002
func TestNmapMaxRate(t *testing.T) {
	for _, tc := range []struct {
		workers, maxRate, wantShare int
	}{
		{workers: 4, maxRate: 300, wantShare: 37},
		{workers: 8, maxRate: 3, wantShare: 1},
		{workers: 3, maxRate: 10, wantShare: 1},
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
				if opts.MaxRate < 1 || opts.MaxRate > tc.wantShare {
					t.Errorf("nmap call MaxRate = %d, want 1..%d", opts.MaxRate, tc.wantShare)
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
					return nil, nil
				},
			}
			settings := inventory.RunSettings{Targets: []string{"10.2.0.0/26"}, Ports: []int{22}, MaxRate: tc.maxRate, Workers: tc.workers, GroupSize: 4}
			st := &scantest.Store{Prev: []string{"10.2.0.200"}}
			s := &scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{}).For}
			if err := s.Run(context.Background(), testRun(settings)); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if peak > tc.maxRate {
				t.Fatalf("concurrent nmap MaxRate sum peaked at %d, want <= %d", peak, tc.maxRate)
			}
			for _, c := range r.Calls() {
				if c.Opts.MaxRate != tc.wantShare {
					t.Fatalf("%s MaxRate = %d, want %d", c.Method, c.Opts.MaxRate, tc.wantShare)
				}
			}
		})
	}
}

// REQ-SCAN-002
func TestPerHostConcurrency(t *testing.T) {
	tr := &scantest.Transport{Hold: make(chan struct{})}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80, 81, 82, 83, 84)}
	settings := inventory.RunSettings{Targets: []string{"10.3.0.1-2"}, Ports: []int{80, 81, 82, 83, 84}, MaxRate: 1000, Workers: 1}
	st := &scantest.Store{}
	s := &scan.Scanner{Store: st, Runner: r, Transport: tr.For}
	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background(), testRun(settings)) }()
	waitFor(t, "2 requests in flight to each host", func() bool {
		a, _ := tr.InFlight("10.3.0.1")
		b, _ := tr.InFlight("10.3.0.2")
		return a == 2 && b == 2
	})
	time.Sleep(50 * time.Millisecond)
	if now, _ := tr.TotalInFlight(); now != 4 {
		t.Fatalf("requests in flight across two hosts = %d, want 4", now)
	}
	close(tr.Hold)
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, h := range []string{"10.3.0.1", "10.3.0.2"} {
		if _, peak := tr.InFlight(h); peak != 2 {
			t.Fatalf("peak requests in flight to %s = %d, want 2", h, peak)
		}
	}
	for _, h := range st.Hosts() {
		if len(h.Services) != 5 {
			t.Fatalf("host %s has %d services, want 5", h.Address, len(h.Services))
		}
		for _, svc := range h.Services {
			if svc.HTTP == nil {
				t.Fatalf("host %s port %d was not probed", h.Address, svc.Port)
			}
		}
	}
}

// REQ-SCAN-003
func TestOnlyAllowedPorts(t *testing.T) {
	tr := &scantest.Transport{}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
		var hosts []nmap.Host
		for _, a := range addrs {
			hosts = append(hosts, nmap.Host{Address: a, Up: true, Ports: []nmap.Port{
				{Number: 80, Protocol: "tcp", State: "open", Service: "http"},
				{Number: 443, Protocol: "tcp", State: "open", Service: "http", Tunnel: "ssl"},
				{Number: 8080, Protocol: "tcp", State: "open", Service: "http-proxy"},
				{Number: 22, Protocol: "tcp", State: "open", Service: "ssh"},
			}})
		}
		return hosts, nil
	}}
	settings := inventory.RunSettings{Targets: []string{"10.4.0.1-3"}, Ports: []int{443, 80}, MaxRate: 100, Workers: 2, GroupSize: 2}
	st := &scantest.Store{Prev: []string{"10.4.0.9"}}
	s := &scan.Scanner{Store: st, Runner: r, Transport: tr.For}
	if err := s.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	calls := r.Calls()
	if len(calls) == 0 {
		t.Fatal("no nmap calls")
	}
	for _, c := range calls {
		for _, p := range c.Opts.ProbePorts {
			if p != 80 && p != 443 {
				t.Fatalf("%s ProbePorts = %v, want a subset of [80 443]", c.Method, c.Opts.ProbePorts)
			}
		}
		if c.Method == "Services" && !slices.Equal(c.Ports, []int{80, 443}) {
			t.Fatalf("Services ports = %v, want [80 443]", c.Ports)
		}
	}
	reqs := tr.Requests()
	if len(reqs) == 0 {
		t.Fatal("no probe requests")
	}
	for _, q := range reqs {
		_, port, _ := strings.Cut(q.Target, ":")
		if port != "80" && port != "443" {
			t.Fatalf("probe request to %s (%s)", q.Target, q.URL)
		}
	}
	hosts := st.Hosts()
	if len(hosts) != 3 {
		t.Fatalf("hosts = %d, want 3", len(hosts))
	}
	for _, h := range hosts {
		var ports []int
		for _, svc := range h.Services {
			ports = append(ports, svc.Port)
		}
		if !slices.Equal(ports, []int{80, 443}) {
			t.Fatalf("host %s recorded ports %v, want [80 443]", h.Address, ports)
		}
		if h.Services[1].HTTP == nil || h.Services[1].HTTP.Scheme != "https" {
			t.Fatalf("host %s port 443 http = %+v, want an https probe", h.Address, h.Services[1].HTTP)
		}
	}
}

// REQ-SCAN-003 REQ-SCAN-005
func TestExcludedNeverContacted(t *testing.T) {
	excluded := map[string]bool{"10.0.0.1": true, "10.0.0.5": true, "10.0.0.6": true}
	var discoverCalls int
	var mu sync.Mutex
	r := &nmaptest.Runner{
		DiscoverFunc: func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			mu.Lock()
			discoverCalls++
			mu.Unlock()
			hosts := []nmap.Host{{Address: "10.0.0.5", Up: true}, {Address: "::ffff:10.0.0.6", Up: true}}
			for _, a := range addrs {
				if a != "10.0.0.3" || len(addrs) == 1 {
					hosts = append(hosts, nmap.Host{Address: a, Up: true})
				}
			}
			return hosts, nil
		},
		ServicesFunc: func(ctx context.Context, addrs []string, ports []int, opts nmap.Options) ([]nmap.Host, error) {
			hosts, _ := openPorts(80)(ctx, append(addrs, "10.0.0.1", "10.0.0.5"), ports, opts)
			return hosts, nil
		},
	}
	tr := &scantest.Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case scantest.Target(req) == "10.0.0.2:80" && req.URL.Path == "/":
			http.Redirect(w, req, "http://10.0.0.200/", http.StatusFound)
		case scantest.Target(req) == "10.0.0.4:80" && req.URL.Path == "/":
			http.Redirect(w, req, "http://10.0.0.5/", http.StatusFound)
		default:
			fmt.Fprint(w, "<title>ok</title>")
		}
	})}
	settings := inventory.RunSettings{
		Targets: []string{"10.0.0.0/28"}, Excludes: []string{"10.0.0.1", "10.0.0.5-6"},
		Ports: []int{80}, MaxRate: 100, Workers: 2, GroupSize: 4,
	}
	st := &scantest.Store{Prev: []string{"10.0.0.1", "10.0.0.3", "10.0.0.6"}}
	s := &scan.Scanner{Store: st, Runner: r, Transport: tr.For}
	if err := s.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	calls := r.Calls()
	for _, c := range calls {
		for _, a := range c.Addrs {
			if excluded[a] {
				t.Fatalf("%s call contains excluded address %s: %v", c.Method, a, c.Addrs)
			}
		}
	}
	reprobe := calls[len(calls)-2]
	if reprobe.Method != "Discover" || !slices.Equal(reprobe.Addrs, []string{"10.0.0.3"}) {
		t.Fatalf("re-probe call = %+v, want Discover of [10.0.0.3]", reprobe)
	}
	for _, q := range tr.Requests() {
		host, _, _ := strings.Cut(q.Target, ":")
		u, _ := url.Parse(q.URL)
		if excluded[host] || excluded[u.Hostname()] || u.Hostname() == "10.0.0.200" {
			t.Fatalf("probe request %s via %s touches an excluded or out-of-scope address", q.URL, q.Target)
		}
	}
	for _, h := range st.Hosts() {
		if excluded[h.Address] {
			t.Fatalf("excluded address %s recorded", h.Address)
		}
	}
	var redirected bool
	for _, h := range st.Hosts() {
		if h.Address == "10.0.0.2" {
			chain := h.Services[0].HTTP.RedirectChain
			redirected = len(chain) == 1 && chain[0] == "http://10.0.0.200/"
		}
	}
	if !redirected {
		t.Fatal("redirect of 10.0.0.2 not recorded in its chain")
	}
	if len(st.Late()) != 1 || len(st.Late()[0]) != 1 || st.Late()[0][0].Address != "10.0.0.3" {
		t.Fatalf("late hosts = %+v, want 10.0.0.3", st.Late())
	}
}

// REQ-SCAN-004
func TestCancelPausesUnit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &scantest.Store{Prev: []string{"10.5.0.250"}}
	var recorded int
	st.AfterRecording = func(inventory.GroupResult) {
		recorded++
		if recorded == 2 {
			cancel()
		}
	}
	r := &nmaptest.Runner{DiscoverFunc: func(ctx context.Context, addrs []string, opts nmap.Options) ([]nmap.Host, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return allUp(ctx, addrs, opts)
	}}
	settings := inventory.RunSettings{Targets: []string{"10.5.0.0/24"}, Ports: []int{80}, MaxRate: 100, Workers: 1, GroupSize: 50}
	err := (&scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{}).For}).Run(ctx, testRun(settings))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if s := st.Statuses(); len(s) != 1 || s[0] != inventory.RunPaused {
		t.Fatalf("statuses = %v, want [paused]", s)
	}
	if len(st.Groups()) != 2 {
		t.Fatalf("recorded groups = %d, want 2", len(st.Groups()))
	}

	run := testRun(settings)
	run.Status = inventory.RunPaused
	before := len(r.Calls())
	if err := (&scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{}).For}).Run(context.Background(), run); err != nil {
		t.Fatalf("resume: %v", err)
	}
	done := map[string]bool{}
	for _, g := range st.Groups()[:2] {
		for _, a := range g.Addresses {
			done[a] = true
		}
	}
	for _, c := range r.Calls()[before:] {
		for _, a := range c.Addrs {
			if done[a] {
				t.Fatalf("resume scanned %s of a finished group", a)
			}
		}
	}
	var all []string
	for _, g := range st.Groups() {
		all = append(all, g.Addresses...)
	}
	slices.Sort(all)
	want := expand(t, settings.Targets, nil)
	slices.Sort(want)
	if !slices.Equal(all, want) {
		t.Fatalf("after resume groups cover %d addresses, want %d", len(all), len(want))
	}
	if s := st.Statuses(); s[len(s)-1] != inventory.RunCompleted {
		t.Fatalf("statuses = %v, want completed last", s)
	}

	run.Status = inventory.RunCompleted
	n := len(r.Calls())
	if err := (&scan.Scanner{Store: st, Runner: r}).Run(context.Background(), run); !errors.Is(err, scan.ErrAlreadyCompleted) ||
		!strings.Contains(err.Error(), "already completed") {
		t.Fatalf("Run(completed) = %v, want ErrAlreadyCompleted", err)
	}
	if len(r.Calls()) != n {
		t.Fatal("Run(completed) made nmap calls")
	}
}

// REQ-SCAN-004
func TestGroupFailureFailsRun(t *testing.T) {
	boom := errors.New("boom")
	r := &nmaptest.Runner{DiscoverFunc: func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
		if addrs[0] == "10.6.0.5" {
			return nil, boom
		}
		return nil, nil
	}}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.6.0.1-8"}, Ports: []int{80}, MaxRate: 100, Workers: 1, GroupSize: 4}
	err := (&scan.Scanner{Store: st, Runner: r}).Run(context.Background(), testRun(settings))
	if !errors.Is(err, boom) {
		t.Fatalf("Run error = %v, want boom", err)
	}
	if s := st.Statuses(); len(s) != 1 || s[0] != inventory.RunFailed {
		t.Fatalf("statuses = %v, want [failed]", s)
	}
}

func TestParsePorts(t *testing.T) {
	got, err := scan.ParsePorts("443, 80,80")
	if err != nil || !slices.Equal(got, []int{80, 443}) {
		t.Fatalf("ParsePorts = %v, %v", got, err)
	}
	for _, bad := range []string{"", "80,abc", "0", "65536", "80,"} {
		if _, err := scan.ParsePorts(bad); err == nil {
			t.Fatalf("ParsePorts(%q) accepted", bad)
		}
	}
}

func TestHTTPSchemesFallback(t *testing.T) {
	tr := &scantest.Transport{}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
		return []nmap.Host{{Address: addrs[0], Up: true, Ports: []nmap.Port{
			{Number: 6379, Protocol: "tcp", State: "open", Service: "redis"},
			{Number: 8000, Protocol: "tcp", State: "open", Service: ""},
			{Number: 8001, Protocol: "tcp", State: "closed", Service: "http"},
		}}}, nil
	}}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.7.0.1"}, Ports: []int{6379, 8000, 8001}, MaxRate: 100, Workers: 1}
	if err := (&scan.Scanner{Store: st, Runner: r, Transport: tr.For}).Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	for _, q := range tr.Requests() {
		if !strings.HasSuffix(q.Target, ":"+strconv.Itoa(8000)) {
			t.Fatalf("unexpected probe of %s", q.Target)
		}
	}
	h := st.Hosts()[0]
	if len(h.Services) != 2 || h.Services[0].Port != 6379 || h.Services[0].HTTP != nil || h.Services[1].HTTP == nil {
		t.Fatalf("services = %+v", h.Services)
	}
}

// REQ-SCAN-006
func TestRunRecordsAddressTotal(t *testing.T) {
	st := &scantest.Store{}
	sc := &scan.Scanner{Store: st, Runner: &nmaptest.Runner{}, Clock: scantest.NewClock(time.Unix(0, 0))}
	run := testRun(inventory.RunSettings{Targets: []string{"10.0.0.0/28"}, Excludes: []string{"10.0.0.5"}, Ports: []int{80}, GroupSize: 4})
	if err := sc.Run(context.Background(), run); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := st.Total(); got != 13 {
		t.Errorf("address total = %d, want 13 (14 hosts of a /28 minus one exclude)", got)
	}
}

type storedSignatures []string

func (s storedSignatures) Enabled(context.Context) ([]detect.Signature, error) {
	var out []detect.Signature
	for _, src := range s {
		sig, err := detect.ParseOne([]byte(src))
		if err != nil {
			return nil, err
		}
		out = append(out, sig)
	}
	return out, nil
}

// REQ-SIGNATURES-003
func TestDatabaseSignaturesJoinDirectorySignatures(t *testing.T) {
	tr := &scantest.Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>x</title>page-a page-b page-c")
	})}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
	settings := inventory.RunSettings{Targets: []string{"10.8.0.1"}, Ports: []int{80}, MaxRate: 100, Workers: 1, SignaturesDir: writeSignatures(t)}
	dbSig := "id: sig-c\nname: C\nkind: custom\nconfidence: 40\nmatch: {all: [{type: body_regex, value: page-c}]}\n"
	st := &scantest.Store{}
	s := &scan.Scanner{Store: st, Runner: r, Transport: tr.For, Signatures: storedSignatures{dbSig}}
	if err := s.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var ids []string
	for _, f := range st.Hosts()[0].Services[0].Findings {
		ids = append(ids, f.SignatureID)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"sig-a", "sig-b", "sig-c"}) {
		t.Fatalf("findings = %v, want directory and database signatures", ids)
	}

	clash := strings.Replace(dbSig, "sig-c", "sig-a", 1)
	s = &scan.Scanner{Store: &scantest.Store{}, Runner: r, Transport: tr.For, Signatures: storedSignatures{clash}}
	err := s.Run(context.Background(), testRun(settings))
	if err == nil || !strings.Contains(err.Error(), detect.RuleDuplicateID) {
		t.Fatalf("Run with an id clash = %v, want the %q rule", err, detect.RuleDuplicateID)
	}
}

// REQ-SCAN-002
func TestMaxRateOneRejected(t *testing.T) {
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
	settings := inventory.RunSettings{Targets: []string{"10.9.1.1"}, Ports: []int{80}, MaxRate: 1, Workers: 1}
	s := &scan.Scanner{Store: &scantest.Store{}, Runner: r, Transport: (&scantest.Transport{}).For}
	if err := s.Run(context.Background(), testRun(settings)); err == nil || !strings.Contains(err.Error(), "max rate 1") {
		t.Fatalf("Run with MaxRate 1 = %v, want a max rate error", err)
	}
	if c := r.Calls(); len(c) != 0 {
		t.Fatalf("nmap calls = %v, want none", c)
	}
}
