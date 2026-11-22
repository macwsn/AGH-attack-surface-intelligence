package scan_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
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

type fakeLAN struct {
	mu     sync.Mutex
	open   map[string][]int
	titles map[string]string
}

func (n *fakeLAN) set(addr string, ports ...int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.open[addr] = ports
}

func (n *fakeLAN) handler(w http.ResponseWriter, r *http.Request) {
	host, _, _ := strings.Cut(scantest.Target(r), ":")
	n.mu.Lock()
	title := n.titles[host]
	n.mu.Unlock()
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprintf(w, "<title>%s</title>", title)
}

func serviceName(port int) string {
	switch port {
	case 22:
		return "ssh"
	case 443:
		return "https"
	case 6379:
		return "redis"
	}
	return "http"
}

func (n *fakeLAN) runner() *nmaptest.Runner {
	return &nmaptest.Runner{
		DiscoverFunc: func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			n.mu.Lock()
			defer n.mu.Unlock()
			var out []nmap.Host
			for _, a := range addrs {
				if _, ok := n.open[a]; ok {
					out = append(out, nmap.Host{Address: a, Up: true})
				}
			}
			return out, nil
		},
		ServicesFunc: func(_ context.Context, addrs []string, ports []int, _ nmap.Options) ([]nmap.Host, error) {
			n.mu.Lock()
			defer n.mu.Unlock()
			var out []nmap.Host
			for _, a := range addrs {
				open, ok := n.open[a]
				if !ok {
					continue
				}
				h := nmap.Host{Address: a, Up: true}
				for _, p := range open {
					if slices.Contains(ports, p) {
						h.Ports = append(h.Ports, nmap.Port{Number: p, Protocol: "tcp", State: "open", Service: serviceName(p)})
					}
				}
				out = append(out, h)
			}
			return out, nil
		},
	}
}

func knownOf(open map[string][]int) []inventory.KnownService {
	var out []inventory.KnownService
	for a, ports := range open {
		for _, p := range ports {
			name := serviceName(p)
			out = append(out, inventory.KnownService{Address: a, Port: p, Protocol: "tcp", Service: name, HTTP: strings.HasPrefix(name, "http")})
		}
	}
	slices.SortFunc(out, func(a, b inventory.KnownService) int {
		if c := netip.MustParseAddr(a.Address).Compare(netip.MustParseAddr(b.Address)); c != 0 {
			return c
		}
		return a.Port - b.Port
	})
	return out
}

func sentPackets(calls []nmaptest.Call, reqs []scantest.Request) int {
	n := len(reqs)
	for _, c := range calls {
		switch c.Method {
		case "Discover":
			n += len(c.Addrs) * (1 + len(c.Opts.ProbePorts))
		case "Services":
			n += len(c.Addrs) * len(c.Ports)
		}
	}
	return n
}

type pair struct {
	addr string
	port int
}

type recheckResult struct {
	runner *nmaptest.Runner
	tr     *scantest.Transport
	store  *scantest.Store
	err    error
}

func runMode(t *testing.T, lan *fakeLAN, known []inventory.KnownService, prev []string, settings inventory.RunSettings) recheckResult {
	t.Helper()
	r := lan.runner()
	tr := &scantest.Transport{Handler: http.HandlerFunc(lan.handler)}
	st := &scantest.Store{Known: known, Prev: prev}
	sc := &scan.Scanner{Store: st, Runner: r, Transport: tr.For}
	err := sc.Run(context.Background(), testRun(settings))
	return recheckResult{runner: r, tr: tr, store: st, err: err}
}

// REQ-SCAN-016
func TestRecheckContactsOnlyKnownServices(t *testing.T) {
	open := map[string][]int{"10.0.0.5": {80, 443}, "10.0.0.9": {22}}
	lan := &fakeLAN{open: map[string][]int{"10.0.0.5": {22, 80, 443}, "10.0.0.9": {22, 80}, "10.0.0.20": {80}, "10.0.0.30": {22}}}
	settings := inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Ports: []int{22, 80, 443}, MaxRate: 1000, Workers: 2, Mode: inventory.ModeRecheck}
	res := runMode(t, lan, knownOf(open), []string{"10.0.0.5", "10.0.0.9", "10.0.0.20", "10.0.0.30"}, settings)
	if res.err != nil {
		t.Fatalf("recheck: %v", res.err)
	}
	knownSet := map[pair]bool{}
	for a, ps := range open {
		for _, p := range ps {
			knownSet[pair{a, p}] = true
		}
	}
	contacted := map[pair]bool{}
	for _, c := range res.runner.Calls() {
		ports := c.Ports
		if c.Method == "Discover" {
			ports = c.Opts.ProbePorts
		}
		for _, a := range c.Addrs {
			if _, ok := open[a]; !ok {
				t.Fatalf("%s contacted unknown address %s: %+v", c.Method, a, c)
			}
			for _, p := range ports {
				if !knownSet[pair{a, p}] {
					t.Fatalf("%s contacted %s:%d outside the known services: %+v", c.Method, a, p, c)
				}
				if c.Method == "Services" {
					contacted[pair{a, p}] = true
				}
			}
		}
	}
	if len(contacted) != len(knownSet) {
		t.Fatalf("services contacted %v, want %v", contacted, knownSet)
	}
	for _, req := range res.tr.Requests() {
		if req.Target != "10.0.0.5:80" && req.Target != "10.0.0.5:443" {
			t.Fatalf("probe request to %s (%s), want only the known HTTP services", req.Target, req.URL)
		}
	}
	if len(res.tr.Requests()) == 0 {
		t.Fatal("no probe request to the known HTTP services")
	}
	var covered []string
	for _, g := range res.store.Groups() {
		for a, ps := range g.CoveredPorts {
			if !slices.Equal(ps, open[a]) {
				t.Fatalf("group %d covers %s ports %v, want %v", g.Index, a, ps, open[a])
			}
		}
		if len(g.CoveredPorts) != len(g.Addresses) {
			t.Fatalf("group %d: covered ports %v for addresses %v", g.Index, g.CoveredPorts, g.Addresses)
		}
		covered = append(covered, g.Addresses...)
	}
	slices.Sort(covered)
	if !slices.Equal(covered, []string{"10.0.0.5", "10.0.0.9"}) {
		t.Fatalf("covered addresses %v", covered)
	}
	for _, h := range res.store.Hosts() {
		for _, s := range h.Services {
			if !knownSet[pair{h.Address, s.Port}] {
				t.Fatalf("recorded service %s:%d outside the known set", h.Address, s.Port)
			}
		}
	}
	if got, want := res.store.Packets(), sentPackets(res.runner.Calls(), res.tr.Requests()); got != want || got == 0 {
		t.Fatalf("recheck packets %d, want %d", got, want)
	}
	if res.store.Total() != 2 {
		t.Fatalf("address total %d, want 2 known hosts", res.store.Total())
	}

	settings.Mode = ""
	full := runMode(t, lan, nil, nil, settings)
	if full.err != nil {
		t.Fatalf("full: %v", full.err)
	}
	var discovered []string
	for _, c := range full.runner.Calls() {
		if c.Method == "Discover" {
			discovered = append(discovered, c.Addrs...)
		}
	}
	slices.Sort(discovered)
	all := expand(t, []string{"10.0.0.0/24"}, nil)
	slices.Sort(all)
	if !slices.Equal(discovered, all) {
		t.Fatalf("full run discovered %d addresses, want %d", len(discovered), len(all))
	}
	if got, want := full.store.Packets(), sentPackets(full.runner.Calls(), full.tr.Requests()); got != want || got == 0 {
		t.Fatalf("full packets %d, want %d", got, want)
	}
}

// REQ-SCAN-016
func TestRecheckReprobeOnlyKnownHosts(t *testing.T) {
	open := map[string][]int{"10.0.0.5": {80}, "10.0.0.9": {22}}
	lan := &fakeLAN{open: map[string][]int{"10.0.0.5": {80}, "10.0.0.20": {80}}}
	settings := inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Ports: []int{22, 80}, MaxRate: 1000, Workers: 1, Mode: inventory.ModeRecheck}
	res := runMode(t, lan, knownOf(open), []string{"10.0.0.5", "10.0.0.9", "10.0.0.20"}, settings)
	if res.err != nil {
		t.Fatal(res.err)
	}
	var discovers [][]string
	for _, c := range res.runner.Calls() {
		if c.Method == "Discover" {
			discovers = append(discovers, c.Addrs)
		}
	}
	last := discovers[len(discovers)-1]
	if !slices.Equal(last, []string{"10.0.0.9"}) {
		t.Fatalf("re-probe discovered %v, want only the missed known host; calls %+v", last, res.runner.Calls())
	}
	if got, want := res.store.Packets(), sentPackets(res.runner.Calls(), res.tr.Requests()); got != want {
		t.Fatalf("packets %d, want %d (re-probe included)", got, want)
	}
}

// REQ-SCAN-016
func TestRecheckHostOrder(t *testing.T) {
	open := map[string][]int{"10.0.0.5": {80}, "10.0.0.9": {22}, "10.0.0.7": {22}}
	lan := &fakeLAN{open: open}
	settings := inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Ports: []int{22, 80}, MaxRate: 1000, Workers: 1, GroupSize: 1,
		Mode: inventory.ModeRecheck, Hosts: []string{"10.0.0.9", "10.0.0.5"}}
	res := runMode(t, lan, knownOf(open), nil, settings)
	if res.err != nil {
		t.Fatal(res.err)
	}
	var order []string
	for _, c := range res.runner.Calls() {
		if c.Method == "Discover" {
			order = append(order, c.Addrs...)
		}
	}
	if !slices.Equal(order, []string{"10.0.0.9", "10.0.0.5"}) {
		t.Fatalf("discover order %v, want the settings' host order", order)
	}
}

// REQ-SCAN-016
func TestRecheckWithoutBase(t *testing.T) {
	lan := &fakeLAN{open: map[string][]int{"10.0.0.5": {80}}}
	settings := inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Ports: []int{80}, MaxRate: 1000, Mode: inventory.ModeRecheck}
	for name, known := range map[string][]inventory.KnownService{
		"no base":         nil,
		"out of targets":  {{Address: "10.0.1.5", Port: 80, Protocol: "tcp", Service: "http"}},
		"outside --ports": {{Address: "10.0.0.5", Port: 22, Protocol: "tcp", Service: "ssh"}},
	} {
		t.Run(name, func(t *testing.T) {
			res := runMode(t, lan, known, nil, settings)
			if res.err == nil || !strings.Contains(res.err.Error(), "no earlier run to recheck") || !errors.Is(res.err, inventory.ErrNoRecheckBase) {
				t.Fatalf("err = %v, want no earlier run to recheck", res.err)
			}
			if n := len(res.runner.Calls()); n != 0 {
				t.Fatalf("%d nmap calls, want 0", n)
			}
			sc := &scan.Scanner{Store: &scantest.Store{Known: known}, Runner: lan.runner()}
			if _, err := sc.PlanRecheck(context.Background(), inventory.Run{Settings: settings}); !errors.Is(err, inventory.ErrNoRecheckBase) {
				t.Fatalf("PlanRecheck err = %v", err)
			}
		})
	}
}

// REQ-SCAN-017
func TestRecheckLabPacketSaving(t *testing.T) {
	lab := map[string][]int{}
	for _, h := range []int{10, 11, 12, 13, 16, 17, 18, 20, 21} {
		lab["172.30.0."+strconv.Itoa(h)] = []int{80}
	}
	lab["172.30.0.14"] = []int{22}
	lab["172.30.0.15"] = []int{6379}
	lan := &fakeLAN{open: lab}
	settings := inventory.RunSettings{
		Targets:  []string{"172.30.0.0/24"},
		Excludes: []string{"172.30.0.1", "172.30.0.2", "172.30.0.3"},
		Ports:    []int{22, 80, 443, 6379, 8000, 8080, 8081},
		MaxRate:  300, Workers: 4,
	}
	full := runMode(t, lan, nil, nil, settings)
	if full.err != nil {
		t.Fatal(full.err)
	}
	if got := len(full.store.Hosts()); got != len(lab) {
		t.Fatalf("full run found %d hosts, want %d", got, len(lab))
	}
	settings.Mode = inventory.ModeRecheck
	re := runMode(t, lan, knownOf(lab), nil, settings)
	if re.err != nil {
		t.Fatal(re.err)
	}
	pf, pr := full.store.Packets(), re.store.Packets()
	if pf != sentPackets(full.runner.Calls(), full.tr.Requests()) || pr != sentPackets(re.runner.Calls(), re.tr.Requests()) {
		t.Fatalf("stored packets %d/%d differ from what was sent", pf, pr)
	}
	t.Logf("packets: full %d, recheck %d", pf, pr)
	if pr == 0 || pr*10 > pf {
		t.Fatalf("recheck sent %d packets, full %d: want at most 10%%", pr, pf)
	}
	if got := len(re.store.Hosts()); got != len(lab) {
		t.Fatalf("recheck found %d hosts, want %d", got, len(lab))
	}
}

// REQ-SCAN-021 REQ-SCAN-016
func TestPlanOfRecheckCountsKnownServicesOnly(t *testing.T) {
	open := map[string][]int{"10.0.0.5": {80, 443}, "10.0.0.9": {22}}
	r := &nmaptest.Runner{}
	tr := &scantest.Transport{}
	s := &scan.Scanner{Store: &scantest.Store{Known: knownOf(open)}, Runner: r, Transport: tr.For}
	settings := inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Ports: []int{22, 80, 443}, MaxRate: 100, Workers: 2, Mode: inventory.ModeRecheck}
	p, err := s.Plan(context.Background(), settings)
	if err != nil {
		t.Fatal(err)
	}
	wantPackets := int64(scan.DiscoveryPackets(1, 2) + scan.ServicePackets(1, 2) + scan.DiscoveryPackets(1, 1) + scan.ServicePackets(1, 1))
	if !p.Recheck || p.Base != "base" || p.Services != 3 || p.Addresses != 2 || fmt.Sprint(p.Ports) != "[22 80 443]" || p.Groups != 1 {
		t.Fatalf("recheck plan = %+v, want 3 known services on 2 hosts from run base", p)
	}
	if p.Packets != wantPackets || p.Requests != 2*scan.RequestsPerPort {
		t.Fatalf("recheck plan packets=%d requests=%d, want %d and %d (two known HTTP services)", p.Packets, p.Requests, wantPackets, 2*scan.RequestsPerPort)
	}
	settings.Mode = ""
	full, err := s.Plan(context.Background(), settings)
	if err != nil || full.Recheck || full.Addresses != 254 {
		t.Fatalf("full plan = %+v, %v", full, err)
	}
	if len(r.Calls()) != 0 || len(tr.Requests()) != 0 {
		t.Fatalf("plan sent nmap calls %v or requests %v", r.Calls(), tr.Requests())
	}
	settings.Mode = inventory.ModeRecheck
	if _, err := (&scan.Scanner{Store: &scantest.Store{}, Runner: r, Transport: tr.For}).Plan(context.Background(), settings); !errors.Is(err, inventory.ErrNoRecheckBase) {
		t.Fatalf("recheck plan without known services: %v, want ErrNoRecheckBase", err)
	}
}

func (n *fakeLAN) paced(latency time.Duration) *nmaptest.Runner {
	r := n.runner()
	discover, services := r.DiscoverFunc, r.ServicesFunc
	wait := func(packets int, opts nmap.Options) {
		time.Sleep(latency + time.Duration(packets)*time.Second/time.Duration(max(opts.MaxRate, 1)))
	}
	r.DiscoverFunc = func(ctx context.Context, addrs []string, opts nmap.Options) ([]nmap.Host, error) {
		wait(len(addrs)*(1+len(opts.ProbePorts)), opts)
		return discover(ctx, addrs, opts)
	}
	r.ServicesFunc = func(ctx context.Context, addrs []string, ports []int, opts nmap.Options) ([]nmap.Host, error) {
		wait(len(addrs)*len(ports), opts)
		return services(ctx, addrs, ports, opts)
	}
	return r
}

// REQ-SCAN-034 AC5: on a /24 with 3% live hosts whose known services differ per host, a recheck is not slower than the full scan
// of the same targets (its nmap calls for different port sets run side by side instead of one after another) and
// sends at most 10% of the full scan's packets. Each fake nmap call takes a start-up latency plus its packets at
// its --max-rate, like nmap.
func TestRecheckOfKnownServicesIsFasterAndCheaperThanFullScan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ports := []int{22, 80, 443, 6379, 8000, 8080, 8081}
		open := map[string][]int{}
		for i := range 8 {
			open[fmt.Sprintf("10.0.0.%d", 10+i*20)] = []int{ports[i%len(ports)], ports[(i+i/len(ports)+1)%len(ports)]}
		}
		lan := &fakeLAN{open: open, titles: map[string]string{}}
		settings := inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Ports: ports, MaxRate: 300, Workers: 4}
		run := func(s inventory.RunSettings) (time.Duration, int) {
			r := lan.paced(2 * time.Second)
			tr := &scantest.Transport{Handler: http.HandlerFunc(lan.handler)}
			sc := &scan.Scanner{Store: &scantest.Store{Known: knownOf(open)}, Runner: r, Transport: tr.For, Clock: bubbleClock{}}
			start := time.Now()
			if err := sc.Run(context.Background(), testRun(s)); err != nil {
				t.Fatalf("%s: %v", s.RunMode(), err)
			}
			return time.Since(start), sentPackets(r.Calls(), tr.Requests())
		}
		fullTime, fullPackets := run(settings)
		settings.Mode = inventory.ModeRecheck
		recheckTime, recheckPackets := run(settings)
		t.Logf("full scan %s %d packets, recheck %s %d packets", fullTime, fullPackets, recheckTime, recheckPackets)
		if recheckTime > fullTime {
			t.Errorf("recheck took %s, the full scan of the same targets %s; want the recheck not slower", recheckTime, fullTime)
		}
		if recheckPackets*10 > fullPackets {
			t.Errorf("recheck sent %d packets, full scan %d; want at most 10%%", recheckPackets, fullPackets)
		}
	})
}
