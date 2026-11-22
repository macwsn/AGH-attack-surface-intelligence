package scan_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

func observe(c *scan.Controller, n int, d time.Duration, timedOut bool) {
	for range n {
		c.Observe(d, timedOut)
	}
}

// REQ-SCAN-018
func TestControllerDecreaseFloorRecovery(t *testing.T) {
	clock := scantest.NewClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	c := scan.NewController(100, clock)
	observe(c, 20, 40*time.Millisecond, false)
	if c.Baseline() != 40*time.Millisecond || c.Rate() != 100 {
		t.Fatalf("after 20 fast probes baseline=%s rate=%d, want 40ms and 100", c.Baseline(), c.Rate())
	}
	observe(c, 20, 81*time.Millisecond, false)
	if c.Rate() != 50 {
		t.Fatalf("median 81ms > 2x40ms: rate = %d, want 50", c.Rate())
	}
	observe(c, 20, 200*time.Millisecond, false)
	if c.Rate() != 50 {
		t.Fatalf("second decrease within %s: rate = %d, want 50", scan.AdaptiveInterval, c.Rate())
	}
	var rates []int
	for range 5 {
		<-clock.After(scan.AdaptiveInterval)
		observe(c, 20, 200*time.Millisecond, false)
		rates = append(rates, c.Rate())
	}
	if want := []int{25, 12, 10, 10, 10}; fmt.Sprint(rates) != fmt.Sprint(want) {
		t.Fatalf("decrease to the floor: rates = %v, want %v", rates, want)
	}
	rates = nil
	for range 12 {
		<-clock.After(scan.AdaptiveInterval)
		observe(c, 20, 60*time.Millisecond, false)
		rates = append(rates, c.Rate())
	}
	if want := []int{20, 30, 40, 50, 60, 70, 80, 90, 100, 100, 100, 100}; fmt.Sprint(rates) != fmt.Sprint(want) {
		t.Fatalf("additive recovery: rates = %v, want %v", rates, want)
	}
}

// REQ-SCAN-018
func TestControllerTimeoutShare(t *testing.T) {
	clock := scantest.NewClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	c := scan.NewController(300, clock)
	observe(c, 18, 5*time.Millisecond, false)
	observe(c, 2, time.Second, true)
	if c.Rate() != 300 {
		t.Fatalf("2 timeouts in 20 (10%%): rate = %d, want 300", c.Rate())
	}
	observe(c, 1, time.Second, true)
	if c.Rate() != 150 {
		t.Fatalf("3 timeouts in 20 (15%%): rate = %d, want 150", c.Rate())
	}
	if c.Floor() != 30 {
		t.Fatalf("floor = %d, want 30 (10%% of 300)", c.Floor())
	}
	if c := scan.NewController(7, clock); c.Floor() != 2 {
		t.Fatalf("floor of max rate 7 = %d, want 2 (one each for nmap and the probe)", c.Floor())
	}
}

func timeoutServers(t *testing.T, n int, timeouts func(i int64) bool) ([]int, *atomic.Int64) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var count atomic.Int64
	var ports []int
	for range n {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" && timeouts(count.Add(1)) {
				select {
				case <-release:
				case <-r.Context().Done():
				}
				return
			}
			fmt.Fprint(w, "<title>ok</title>")
		}))
		t.Cleanup(srv.Close)
		u, _ := url.Parse(srv.URL)
		p, _ := strconv.Atoi(u.Port())
		ports = append(ports, p)
	}
	return ports, &count
}

// REQ-SCAN-019
func TestHostPausedAfterThreeTimeouts(t *testing.T) {
	ports, roots := timeoutServers(t, 12, func(int64) bool { return true })
	st := &scantest.Store{Prev: []string{"127.0.0.1"}}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(ports...)}
	settings := inventory.RunSettings{Targets: []string{"127.0.0.1"}, Ports: ports, MaxRate: 100, Workers: 1, HTTPTimeoutMS: 100}
	if err := (&scan.Scanner{Store: st, Runner: r}).Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	if n := roots.Load(); n > 2*(scan.PauseAfterTimeouts+scan.PerHostConcurrency-1) {
		t.Fatalf("root requests to a host that always times out = %d over 12 ports, want at most %d (paused, then one retry)",
			n, 2*(scan.PauseAfterTimeouts+scan.PerHostConcurrency-1))
	}
	groups := st.Groups()
	if len(groups) != 1 || len(groups[0].Hosts) != 1 || len(groups[0].Hosts[0].Services) != 12 {
		t.Fatalf("groups = %+v, want the paused host recorded in its group with 12 services", groups)
	}
	for _, s := range groups[0].Hosts[0].Services {
		if s.State != "open" || s.HTTP == nil || s.HTTP.Error != "timeout" || s.HTTP.URL != fmt.Sprintf("http://127.0.0.1:%d/", s.Port) {
			t.Errorf("service %d = %+v, http %+v; want open with http.error timeout and its URL", s.Port, s, s.HTTP)
		}
	}
	if f, _ := st.FailedGroups(context.Background(), 1); len(f) != 0 {
		t.Fatalf("failed groups = %+v, want none", f)
	}
	if late := st.Late(); len(late) != 0 {
		t.Fatalf("re-probe = %+v: the paused host was not found missing, so it must not be re-probed", late)
	}
}

// REQ-SCAN-019
func TestHostPauseRetriedAtEnd(t *testing.T) {
	ports, _ := timeoutServers(t, 12, func(i int64) bool { return i <= int64(scan.PauseAfterTimeouts+scan.PerHostConcurrency-1) })
	st := &scantest.Store{}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(ports...)}
	settings := inventory.RunSettings{Targets: []string{"127.0.0.1"}, Ports: ports, MaxRate: 1000, Workers: 1, HTTPTimeoutMS: 100}
	if err := (&scan.Scanner{Store: st, Runner: r}).Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	hosts := st.Hosts()
	if len(hosts) != 1 || len(hosts[0].Services) != 12 {
		t.Fatalf("hosts = %+v", hosts)
	}
	for _, s := range hosts[0].Services {
		if s.HTTP == nil || s.HTTP.StatusCode != http.StatusOK || s.HTTP.Title != "ok" {
			t.Errorf("service %d after the retry = %+v, want 200 ok", s.Port, s.HTTP)
		}
	}
}

type slowTransport struct {
	tr   *scantest.Transport
	fast int64
	n    atomic.Int64
}

func (s *slowTransport) For(target string) http.RoundTripper {
	next := s.tr.For(target)
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if s.n.Add(1) > s.fast {
			time.Sleep(30 * time.Millisecond)
		}
		return next.RoundTrip(req)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// REQ-SCAN-020
// Sent is the measured probe HTTP requests only: this proves the probe limiter keeps them under the limits. It says
// nothing about nmap, whose packets are estimated (RateSample.Packets) and bounded only by nmap's own --max-rate.
func TestRateSamplesNeverExceedLimit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		noAdaptive bool
		fast       int64
		backedOff  bool
	}{
		{name: "steady", fast: 1 << 30},
		{name: "slow targets", fast: 40, backedOff: true},
		{name: "slow targets, no adaptive", fast: 40, noAdaptive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := scantest.NewClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			inner := &scantest.Transport{Clock: clock}
			tr := &slowTransport{tr: inner, fast: tc.fast}
			st := &scantest.Store{}
			r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
			settings := inventory.RunSettings{Targets: []string{"10.9.0.0/23"}, Ports: []int{80}, MaxRate: 20, Workers: 2,
				GroupSize: 16, NoAdaptive: tc.noAdaptive}
			if err := (&scan.Scanner{Store: st, Runner: r, Clock: clock, Transport: tr.For}).Run(context.Background(), testRun(settings)); err != nil {
				t.Fatal(err)
			}
			samples := st.RateSamples()
			if len(samples) < 2 {
				t.Fatalf("samples = %+v, want several minutes", samples)
			}
			sent, backedOff := 0, false
			for _, s := range samples {
				sent += s.Sent
				if s.Configured != 20 || s.Effective < 2 || s.Effective > s.Configured {
					t.Errorf("sample %+v: want configured 20 and effective in [2, 20]", s)
				}
				if s.PerSecond() > float64(s.Configured) {
					t.Errorf("sample %+v: actual %.2f/s exceeds the max rate %d", s, s.PerSecond(), s.Configured)
				}
				if !tc.backedOff && s.PerSecond() > float64(s.Effective) {
					t.Errorf("sample %+v: actual %.2f/s exceeds the effective limit %d", s, s.PerSecond(), s.Effective)
				}
				backedOff = backedOff || s.Effective < s.Configured
			}
			if want := len(inner.Requests()); sent < want {
				t.Errorf("sum of sent = %d, want at least the %d probe requests", sent, want)
			}
			if backedOff != tc.backedOff {
				t.Errorf("effective limit lowered = %t, want %t (samples %+v)", backedOff, tc.backedOff, samples)
			}
			rs := scan.SummarizeRate(samples)
			if rs.Peak > 20 || rs.Average > rs.Peak || rs.Average <= 0 {
				t.Errorf("summary = %+v", rs)
			}
		})
	}
}

// REQ-SCAN-021
func TestPlanSendsNothing(t *testing.T) {
	r := &nmaptest.Runner{}
	tr := &scantest.Transport{}
	s := &scan.Scanner{Store: &scantest.Store{}, Runner: r, Transport: tr.For}
	p, err := s.Plan(context.Background(), inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Excludes: []string{"10.0.0.0/28"},
		Ports: []int{443, 80}, MaxRate: 100, Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	n := len(expand(t, []string{"10.0.0.0/24"}, []string{"10.0.0.0/28"}))
	if p.Addresses != n || fmt.Sprint(p.Ports) != "[80 443]" || p.Groups != 4 || p.GroupSize != scan.InitialGroupSize {
		t.Fatalf("plan = %+v, want %d addresses, ports [80 443], 4 groups of 64", p, n)
	}
	if want := int64(n*3*2 + n*2*10); p.Packets != want || p.Requests != int64(n*2*86) {
		t.Fatalf("worst case packets=%d requests=%d, want %d and %d", p.Packets, p.Requests, want, n*2*86)
	}
	if want := time.Duration(n*2*86/50) * time.Second; p.AtMaxRate.Round(time.Second) != want.Round(time.Second) || !p.Adaptive || p.MeasuredKnown() {
		t.Fatalf("plan = %+v, want requests / 50 per second at max rate, adaptive, no measured speed", p)
	}
	p.Measured(float64(n) / 60)
	if p.AtMeasured != time.Minute {
		t.Fatalf("at n/60 addresses/s: %s, want 1m0s", p.AtMeasured)
	}
	if c := r.Calls(); len(c) != 0 {
		t.Fatalf("nmap calls = %v, want none", c)
	}
	if q := tr.Requests(); len(q) != 0 {
		t.Fatalf("requests = %v, want none", q)
	}
}

// REQ-SCAN-020: the samples keep what is measured (probe HTTP requests) apart from what is estimated (nmap packets),
// and the run's packet count is the sum of both.
func TestRateSamplesSplitMeasuredRequestsFromEstimatedPackets(t *testing.T) {
	clock := scantest.NewClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	tr := &scantest.Transport{Clock: clock}
	st := &scantest.Store{}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
	settings := inventory.RunSettings{Targets: []string{"10.9.0.0/26"}, Ports: []int{80, 443}, MaxRate: 20, Workers: 2, GroupSize: 16}
	if err := (&scan.Scanner{Store: st, Runner: r, Clock: clock, Transport: tr.For}).Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	nmapPackets := sentPackets(r.Calls(), nil)
	rs := scan.SummarizeRate(st.RateSamples())
	if rs.Requests != len(tr.Requests()) || rs.Requests == 0 {
		t.Errorf("measured requests in the samples = %d, want the %d requests the transport saw", rs.Requests, len(tr.Requests()))
	}
	if rs.Packets != nmapPackets || rs.Packets == 0 {
		t.Errorf("estimated packets in the samples = %d, want %d from the nmap calls", rs.Packets, nmapPackets)
	}
	if got := rs.Requests + rs.Packets; got != st.Packets() {
		t.Errorf("samples hold %d requests + %d packets = %d, run packets = %d: want one formula", rs.Requests, rs.Packets, got, st.Packets())
	}
}

// REQ-SCAN-020: what the limiter guarantees is that the measured probe requests stay within the probe's half of the
// effective limit in every minute; nmap packets are estimated and only bounded by nmap's own --max-rate.
func TestMeasuredRequestsStayWithinProbeShare(t *testing.T) {
	for _, noAdaptive := range []bool{false, true} {
		clock := scantest.NewClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		inner := &scantest.Transport{Clock: clock}
		tr := &slowTransport{tr: inner, fast: 40}
		st := &scantest.Store{}
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
		settings := inventory.RunSettings{Targets: []string{"10.9.0.0/24"}, Ports: []int{80}, MaxRate: 20, Workers: 2,
			GroupSize: 16, NoAdaptive: noAdaptive}
		if err := (&scan.Scanner{Store: st, Runner: r, Clock: clock, Transport: tr.For}).Run(context.Background(), testRun(settings)); err != nil {
			t.Fatal(err)
		}
		for _, s := range st.RateSamples() {
			if share := s.Configured - s.Configured/2; s.Sent > 60*share {
				t.Errorf("adaptive off=%t sample %+v: %d measured requests exceed 60 x the probe share %d", noAdaptive, s, s.Sent, share)
			}
		}
	}
}

// REQ-SCAN-019: at a low max rate the controller never goes below one nmap packet per second per slot plus as much
// for the probe, and the plan states that minimum.
func TestLowMaxRateMinimumIsOnePacketPerSlot(t *testing.T) {
	s := &scan.Scanner{Store: &scantest.Store{}, Runner: &nmaptest.Runner{}, Transport: (&scantest.Transport{}).For}
	p, err := s.Plan(context.Background(), inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Ports: []int{80}, MaxRate: 10, Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	if p.Slots != 4 || p.MinRate != 8 {
		t.Fatalf("plan slots=%d min rate=%d, want 4 slots and 8 per second (old floor 2 cannot be kept by 4 nmap slots)", p.Slots, p.MinRate)
	}
	if p, _ := s.Plan(context.Background(), inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Ports: []int{80}, MaxRate: 300, Workers: 4}); p.MinRate != 30 {
		t.Fatalf("min rate at max rate 300 = %d, want the 10%% floor 30", p.MinRate)
	}

	clock := scantest.NewClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	tr := &slowTransport{tr: &scantest.Transport{Clock: clock}, fast: 40}
	st := &scantest.Store{}
	r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
	settings := inventory.RunSettings{Targets: []string{"10.9.0.0/24"}, Ports: []int{80}, MaxRate: 10, Workers: 4, GroupSize: 16}
	if err := (&scan.Scanner{Store: st, Runner: r, Clock: clock, Transport: tr.For}).Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	lowest := 10
	for _, s := range st.RateSamples() {
		lowest = min(lowest, s.Effective)
	}
	if lowest != 8 {
		t.Errorf("lowest effective limit = %d, want the real minimum 8", lowest)
	}
	for _, c := range r.Calls() {
		if c.Opts.MaxRate < 1 || c.Opts.MaxRate*4 > lowest/2 {
			t.Errorf("nmap call %+v: %d per second per slot over 4 slots exceeds nmap's half of %d", c, c.Opts.MaxRate, lowest)
		}
	}
}
