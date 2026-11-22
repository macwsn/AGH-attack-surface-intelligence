//go:build integration

package scan_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"asi/internal/diff"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func openInventory(t *testing.T) *inventory.Inventory {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	k, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.New(s, k)
}

type network struct {
	up      map[string]bool
	lateUp  map[string]bool
	mu      sync.Mutex
	asked   map[string]int
	handler http.Handler
}

func newNetwork(up, lateUp []string) *network {
	n := &network{up: map[string]bool{}, lateUp: map[string]bool{}, asked: map[string]int{}}
	for _, a := range up {
		n.up[a] = true
	}
	for _, a := range lateUp {
		n.lateUp[a] = true
	}
	n.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "lab")
		fmt.Fprintf(w, "<title>site %s</title>", scantest.Target(r))
	})
	return n
}

func (n *network) runner() *nmaptest.Runner {
	return &nmaptest.Runner{
		DiscoverFunc: func(ctx context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			n.mu.Lock()
			defer n.mu.Unlock()
			var hosts []nmap.Host
			for _, a := range addrs {
				n.asked[a]++
				if n.up[a] || (n.lateUp[a] && n.asked[a] > 1) {
					hosts = append(hosts, nmap.Host{Address: a, Up: true})
				}
			}
			return hosts, nil
		},
		ServicesFunc: func(ctx context.Context, addrs []string, ports []int, _ nmap.Options) ([]nmap.Host, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var hosts []nmap.Host
			for _, a := range addrs {
				hosts = append(hosts, nmap.Host{Address: a, Up: true, Ports: []nmap.Port{
					{Number: 22, Protocol: "tcp", State: "open", Service: "ssh", Product: "OpenSSH"},
					{Number: 80, Protocol: "tcp", State: "open", Service: "http", Product: "nginx"},
				}})
			}
			return hosts, nil
		},
	}
}

type cancellingStore struct {
	*inventory.Inventory
	after  int
	cancel context.CancelFunc
	mu     sync.Mutex
	n      int
}

func (s *cancellingStore) RecordGroup(ctx context.Context, runID int64, g inventory.GroupResult) error {
	if err := s.Inventory.RecordGroup(ctx, runID, g); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	if s.n == s.after {
		s.cancel()
	}
	return nil
}

func settingsFor(include, exclude []string, groupSize int) inventory.RunSettings {
	return inventory.RunSettings{Targets: include, Excludes: exclude, Ports: []int{22, 80}, MaxRate: 1000, Workers: 1, GroupSize: groupSize}
}

func scanRun(t *testing.T, st scan.Store, inv *inventory.Inventory, n *network, name string, inactiveAfter int, settings inventory.RunSettings) (*nmaptest.Runner, error) {
	t.Helper()
	run, err := inv.CreateRun(context.Background(), inventory.RunSpec{Name: name, InactiveAfter: inactiveAfter, Settings: settings})
	if err != nil {
		t.Fatalf("CreateRun %s: %v", name, err)
	}
	r := n.runner()
	tr := &scantest.Transport{Handler: n.handler}
	return r, (&scan.Scanner{Store: st, Runner: r, Transport: tr.For}).Run(context.Background(), run)
}

func mustScan(t *testing.T, inv *inventory.Inventory, n *network, name string, inactiveAfter int, settings inventory.RunSettings) *nmaptest.Runner {
	t.Helper()
	r, err := scanRun(t, inv, inv, n, name, inactiveAfter, settings)
	if err != nil {
		t.Fatalf("scan %s: %v", name, err)
	}
	return r
}

func exportAsOf(t *testing.T, inv *inventory.Inventory, run string) inventory.Export {
	t.Helper()
	e, err := inv.Export(context.Background(), run)
	if err != nil {
		t.Fatalf("Export(%q): %v", run, err)
	}
	return e
}

func hostOf(t *testing.T, e inventory.Export, addr string) inventory.ExportHost {
	t.Helper()
	for _, h := range e.Hosts {
		if h.Address == addr {
			return h
		}
	}
	t.Fatalf("export of %s has no host %s", e.Run, addr)
	return inventory.ExportHost{}
}

func comparable(t *testing.T, e inventory.Export) string {
	t.Helper()
	e.GeneratedAt = time.Time{}
	for i := range e.Hosts {
		e.Hosts[i].FirstSeen, e.Hosts[i].LastSeen = time.Time{}, time.Time{}
		for j := range e.Hosts[i].Services {
			e.Hosts[i].Services[j].FirstSeen, e.Hosts[i].Services[j].LastSeen = time.Time{}, time.Time{}
		}
	}
	b, err := json.MarshalIndent(e, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// REQ-SCAN-001
func TestRunRecordsGroups(t *testing.T) {
	inv := openInventory(t)
	include, exclude := []string{"10.8.0.0/27"}, []string{"10.8.0.3"}
	var up []string
	for _, a := range expand(t, include, nil) {
		if a[len(a)-1]%3 == 0 {
			up = append(up, a)
		}
	}
	n := newNetwork(up, nil)
	mustScan(t, inv, n, "g1", 3, settingsFor(include, exclude, 7))
	run, err := inv.RunByName(context.Background(), "g1")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != inventory.RunCompleted {
		t.Fatalf("status = %s, want completed", run.Status)
	}
	groups, err := inv.RunGroups(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	var addresses, found int
	for i, g := range groups {
		if g.Index != i || g.Duration < 0 || g.AddressCount != len(g.Addresses) {
			t.Fatalf("group %d = %+v", i, g)
		}
		addresses += g.AddressCount
		found += g.HostsFound
	}
	if want := len(expand(t, include, exclude)); addresses != want || len(groups) != (want+6)/7 {
		t.Fatalf("groups %d cover %d addresses, want %d in %d groups", len(groups), addresses, want, (want+6)/7)
	}
	seen := 0
	for _, h := range exportAsOf(t, inv, "g1").Hosts {
		if h.MissedRuns == 0 && h.Status == inventory.StatusActive {
			seen++
		}
	}
	if found != seen || seen == 0 {
		t.Fatalf("hosts found in groups = %d, seen in export = %d", found, seen)
	}
}

// REQ-SCAN-004
func TestCancelPauses(t *testing.T) {
	inv := openInventory(t)
	include := []string{"10.9.0.0/27"}
	all := expand(t, include, nil)
	n := newNetwork(all, nil)
	mustScan(t, inv, n, "before", 3, settingsFor(include, nil, 8))
	n.up["10.9.0.2"] = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &cancellingStore{Inventory: inv, after: 2, cancel: cancel}
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "c1", Settings: settingsFor(include, nil, 8)})
	if err != nil {
		t.Fatal(err)
	}
	r := n.runner()
	err = (&scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{Handler: n.handler}).For}).Run(ctx, run)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	got, err := inv.RunByName(context.Background(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != inventory.RunPaused || got.FinishedAt != nil {
		t.Fatalf("status = %s finished %v, want paused", got.Status, got.FinishedAt)
	}
	groups, err := inv.RunGroups(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0].Index != 0 || groups[1].Index != 1 {
		t.Fatalf("groups = %+v, want groups 0 and 1", groups)
	}
	for _, g := range groups {
		if g.AddressCount != 8 || g.Duration < 0 {
			t.Fatalf("group %+v, want 8 addresses and a duration", g)
		}
	}
	for _, c := range r.Calls() {
		if slices.Equal(c.Addrs, []string{"10.9.0.2"}) {
			t.Fatalf("paused run re-probed: %+v", c)
		}
	}
}

// REQ-SCAN-004
func TestResume(t *testing.T) {
	include, exclude := []string{"10.12.0.0/27"}, []string{"10.12.0.9"}
	all := expand(t, include, exclude)
	var first, second []string
	for _, a := range all {
		switch a[len(a)-1] % 4 {
		case 0, 1:
			first = append(first, a)
			second = append(second, a)
		case 2:
			first = append(first, a)
		}
	}
	late := []string{"10.12.0.2", "10.12.0.26"}

	scanBoth := func(t *testing.T, interrupt bool) (*inventory.Inventory, string) {
		inv := openInventory(t)
		mustScan(t, inv, newNetwork(first, nil), "p", 2, settingsFor(include, exclude, 6))
		n := newNetwork(second, late)
		if !interrupt {
			mustScan(t, inv, n, "r", 2, settingsFor(include, exclude, 6))
			return inv, comparable(t, exportAsOf(t, inv, "r"))
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "r", InactiveAfter: 2, Settings: settingsFor(include, exclude, 6)})
		if err != nil {
			t.Fatal(err)
		}
		r := n.runner()
		st := &cancellingStore{Inventory: inv, after: 2, cancel: cancel}
		if err := (&scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{Handler: n.handler}).For}).Run(ctx, run); !errors.Is(err, context.Canceled) {
			t.Fatalf("interrupted run: %v", err)
		}
		paused, err := inv.RunByName(context.Background(), "r")
		if err != nil || paused.Status != inventory.RunPaused {
			t.Fatalf("after interrupt: %+v, %v", paused, err)
		}
		groups, err := inv.RunGroups(context.Background(), run.ID)
		if err != nil {
			t.Fatal(err)
		}
		done := map[string]bool{}
		for _, g := range groups {
			for _, a := range g.Addresses {
				done[a] = true
			}
		}
		r2 := n.runner()
		if err := (&scan.Scanner{Store: inv, Runner: r2, Transport: (&scantest.Transport{Handler: n.handler}).For}).Run(context.Background(), paused); err != nil {
			t.Fatalf("resume: %v", err)
		}
		calls := r2.Calls()
		reprobe := len(calls)
		for i, c := range calls {
			if c.Method == "Discover" {
				reprobe = i
			}
		}
		for i, c := range calls {
			for _, a := range c.Addrs {
				if i < reprobe && done[a] {
					t.Fatalf("resume %s call scanned %s from a group finished before the pause", c.Method, a)
				}
				if i >= reprobe && (!slices.Contains(first, a) || slices.Contains(second, a)) {
					t.Fatalf("end-of-run re-probe %s contains %s, which was not live before and missing now", c.Method, a)
				}
			}
		}
		completed, err := inv.RunByName(context.Background(), "r")
		if err != nil || completed.Status != inventory.RunCompleted {
			t.Fatalf("after resume: %+v, %v", completed, err)
		}
		return inv, comparable(t, exportAsOf(t, inv, "r"))
	}

	_, want := scanBoth(t, false)
	inv, got := scanBoth(t, true)
	if got != want {
		t.Fatalf("resumed export differs from an uninterrupted run:\n got %s\nwant %s", got, want)
	}
	if !strings.Contains(got, `"status": "unstable"`) || !strings.Contains(got, `"address": "10.12.0.26"`) {
		t.Fatalf("export lacks the expected mix of statuses: %s", got)
	}

	run, err := inv.RunByName(context.Background(), "r")
	if err != nil {
		t.Fatal(err)
	}
	groupsBefore, _ := inv.RunGroups(context.Background(), run.ID)
	r := newNetwork(second, nil).runner()
	err = (&scan.Scanner{Store: inv, Runner: r}).Run(context.Background(), run)
	if !errors.Is(err, scan.ErrAlreadyCompleted) || !strings.Contains(err.Error(), "already completed") {
		t.Fatalf("resume of a completed run = %v, want already completed", err)
	}
	groupsAfter, _ := inv.RunGroups(context.Background(), run.ID)
	after, _ := inv.RunByName(context.Background(), "r")
	if len(r.Calls()) != 0 || !reflect.DeepEqual(groupsBefore, groupsAfter) || after.Status != inventory.RunCompleted ||
		comparable(t, exportAsOf(t, inv, "r")) != got {
		t.Fatal("resume of a completed run changed something")
	}
}

// REQ-SCAN-005
func TestReprobeMissing(t *testing.T) {
	inv := openInventory(t)
	include := []string{"10.10.0.0/28"}
	const a, b, c = "10.10.0.5", "10.10.0.6", "10.10.0.7"
	mustScan(t, inv, newNetwork([]string{a, b, c}, nil), "m1", 2, settingsFor(include, nil, 4))

	r := mustScan(t, inv, newNetwork([]string{c}, []string{a}), "m2", 2, settingsFor(include, nil, 4))
	var reprobes []nmaptest.Call
	asked := map[string]int{}
	for _, call := range r.Calls() {
		if call.Method == "Discover" {
			for _, x := range call.Addrs {
				asked[x]++
			}
		}
		if slices.Contains(call.Addrs, a) && len(call.Addrs) <= 2 {
			reprobes = append(reprobes, call)
		}
	}
	if len(reprobes) != 2 || !slices.Equal(reprobes[0].Addrs, []string{a, b}) || !slices.Equal(reprobes[1].Addrs, []string{a}) ||
		reprobes[1].Method != "Services" || !slices.Equal(reprobes[1].Ports, []int{22, 80}) {
		t.Fatalf("re-probe calls = %+v, want Discover [a b] then Services [a] on [22 80]", reprobes)
	}
	if asked[a] != 2 || asked[b] != 2 || asked[c] != 1 {
		t.Fatalf("discover counts = %v, want a and b twice, c once", asked)
	}
	e := exportAsOf(t, inv, "m2")
	ha := hostOf(t, e, a)
	if ha.Status != inventory.StatusActive || ha.MissedRuns != 0 || len(ha.Services) != 2 || ha.Services[1].HTTP == nil ||
		ha.Services[1].Status != inventory.StatusActive {
		t.Fatalf("host found on re-probe = %+v", ha)
	}
	if hb := hostOf(t, e, b); hb.Status != inventory.StatusUnstable || hb.MissedRuns != 1 {
		t.Fatalf("host still down = %s missed %d, want unstable 1", hb.Status, hb.MissedRuns)
	}

	r = mustScan(t, inv, newNetwork([]string{a, c}, nil), "m3", 2, settingsFor(include, nil, 4))
	if hb := hostOf(t, exportAsOf(t, inv, "m3"), b); hb.Status != inventory.StatusInactive || hb.MissedRuns != 2 {
		t.Fatalf("host missed twice = %s missed %d, want inactive 2", hb.Status, hb.MissedRuns)
	}
	last := r.Calls()[len(r.Calls())-1]
	if last.Method != "Discover" || !slices.Equal(last.Addrs, []string{b}) {
		t.Fatalf("last call of m3 = %+v, want the single re-probe of %s", last, b)
	}
}

// REQ-SCAN-005
func TestReprobeBoundaries(t *testing.T) {
	inv := openInventory(t)
	include := []string{"10.11.0.0/28"}
	const gone, stays, excluded, never = "10.11.0.4", "10.11.0.5", "10.11.0.6", "10.11.0.7"
	mustScan(t, inv, newNetwork([]string{gone, stays, excluded}, nil), "b1", 1, settingsFor(include, nil, 4))
	mustScan(t, inv, newNetwork([]string{stays, excluded}, nil), "b2", 1, settingsFor(include, nil, 4))
	if h := hostOf(t, exportAsOf(t, inv, "b2"), gone); h.Status != inventory.StatusInactive {
		t.Fatalf("%s after b2 = %s, want inactive", gone, h.Status)
	}

	r := mustScan(t, inv, newNetwork([]string{stays}, nil), "b3", 1, settingsFor(include, []string{excluded}, 4))
	groups := (len(expand(t, include, []string{excluded})) + 3) / 4
	discovers, services := 0, 0
	for _, c := range r.Calls() {
		for _, x := range c.Addrs {
			if x == excluded {
				t.Fatalf("%s call contains the excluded address", c.Method)
			}
		}
		switch c.Method {
		case "Discover":
			discovers++
		case "Services":
			services++
			if !slices.Equal(c.Addrs, []string{stays}) {
				t.Fatalf("Services call %v, want only %s", c.Addrs, stays)
			}
		}
	}
	if discovers != groups || services != 1 {
		t.Fatalf("b3 made %d Discover and %d Services calls, want %d and 1 (no re-probe of %s, %s, %s)",
			discovers, services, groups, gone, excluded, never)
	}
}

// REQ-DIFF-003
func TestServiceGoneAndBackOnHostThatStaysUp(t *testing.T) {
	inv := openInventory(t)
	ctx := context.Background()
	var (
		mu   sync.Mutex
		down bool
	)
	r := &nmaptest.Runner{
		DiscoverFunc: func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			return []nmap.Host{{Address: addrs[0], Up: true}}, nil
		},
		ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
			mu.Lock()
			defer mu.Unlock()
			state := "open"
			if down {
				state = "closed"
			}
			return []nmap.Host{{Address: addrs[0], Up: true, Ports: []nmap.Port{
				{Number: 3001, Protocol: "tcp", State: "open", Service: "ssh", Product: "OpenSSH"},
				{Number: 8787, Protocol: "tcp", State: state, Service: "ssh", Product: "OpenSSH"},
			}}}, nil
		},
	}
	settings := inventory.RunSettings{Targets: []string{"localhost"}, Ports: []int{3001, 8787}, MaxRate: 100, Workers: 1}
	steps := []struct {
		down bool
		want string
	}{{false, ""}, {true, diff.ServiceMissing}, {true, diff.ServiceInactive}, {true, ""}, {false, diff.ServiceReturned}}
	var prev inventory.Export
	for i, step := range steps {
		mu.Lock()
		down = step.down
		mu.Unlock()
		name := fmt.Sprintf("svc-%d", i)
		run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name, InactiveAfter: 2, Settings: settings})
		if err != nil {
			t.Fatal(err)
		}
		sc := &scan.Scanner{Store: inv, Runner: r, Resolver: resolverFunc(func(string) string { return "127.0.0.1" }), Transport: (&scantest.Transport{}).For}
		if err := sc.Run(ctx, run); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cur := exportAsOf(t, inv, name)
		h := hostOf(t, cur, "127.0.0.1")
		if h.Status != inventory.StatusActive || !slices.Equal(h.Hostnames, []string{"localhost"}) {
			t.Fatalf("%s: host status %s hostnames %v, want active [localhost]", name, h.Status, h.Hostnames)
		}
		if i == 0 {
			prev = cur
			continue
		}
		d := diff.Compute(prev, cur, diff.Options{})
		var got []string
		for _, c := range d.Changes {
			if c.Port == nil {
				t.Fatalf("%s: host-level change %+v", name, c)
			}
			got = append(got, fmt.Sprintf("%s %d", c.Type, *c.Port))
		}
		var want []string
		if step.want != "" {
			want = []string{step.want + " 8787"}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("diff %s -> %s = %v, want %v", prev.Run, name, got, want)
		}
		prev = cur
	}
}

type resolverFunc func(host string) string

func (f resolverFunc) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr(f(host))}, nil
}

// REQ-DIFF-014, REQ-DIFF-016, REQ-SCAN-031
func TestPerRequestNoiseIsNoChangeOverFiveScans(t *testing.T) {
	inv := openInventory(t)
	include := []string{"10.12.0.1"}
	n := newNetwork(include, nil)
	var mu sync.Mutex
	counter := 0
	next := func() int {
		mu.Lock()
		defer mu.Unlock()
		counter++
		return counter
	}
	n.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			nonce := make([]byte, 16)
			rand.Read(nonce)
			w.Header().Set("Content-Security-Policy", fmt.Sprintf("script-src 'self' 'unsafe-inline' 'nonce-%x' 'strict-dynamic'; object-src 'none'", nonce))
			w.Header().Set("Server", "lab")
			fmt.Fprint(w, "<title>Adminer</title>")
		case "/favicon.ico":
			fmt.Fprintf(w, "icon-%d", next())
		default:
			http.NotFound(w, r)
		}
	})
	settings := settingsFor(include, nil, 0)
	var runs []string
	for i := range 5 {
		name := fmt.Sprintf("noise%d", i)
		mustScan(t, inv, n, name, 3, settings)
		runs = append(runs, name)
	}
	for i := 1; i < len(runs); i++ {
		d, err := diff.Between(context.Background(), inv, runs[i-1], runs[i], diff.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Changes) != 0 {
			t.Errorf("%s -> %s: changes = %+v, want none", runs[i-1], runs[i], d.Changes)
		}
	}
	h := hostOf(t, exportAsOf(t, inv, runs[len(runs)-1]), include[0])
	for _, s := range h.Services {
		if s.Port != 80 {
			continue
		}
		if s.HTTP == nil || !strings.Contains(s.HTTP.Headers["content-security-policy"], "'nonce-") || strings.Contains(s.HTTP.Headers["content-security-policy"], "<volatile>") {
			t.Errorf("stored http = %+v, want the raw CSP header", s.HTTP)
		}
		if s.HTTP != nil && !s.HTTP.FaviconUnstable {
			t.Errorf("favicon %q not recorded as unstable", s.HTTP.FaviconSHA256)
		}
	}
}
