package scan_test

import (
	"context"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
	"asi/internal/targets"
)

type largeResult struct {
	addresses  int
	live       int
	peakHeap   uint64
	peakNmap   int
	groupSizes []int
}

func scanLarge(t testing.TB) largeResult {
	t.Helper()
	include := []string{"10.0.0.0/18", "10.0.0.0", "10.0.63.255"}
	in, err := targets.Parse(strings.NewReader(strings.Join(include, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	set, err := targets.Build(context.Background(), in, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var all []string
	for tg := range set.All() {
		all = append(all, tg.Addr.String())
	}
	live := map[string]bool{}
	for i, a := range all {
		if i%100 < 3 {
			live[a] = true
		}
	}
	var (
		mu       sync.Mutex
		inFlight int
		peakNmap int
	)
	r := &nmaptest.Runner{
		DiscoverFunc: func(ctx context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			mu.Lock()
			inFlight++
			peakNmap = max(peakNmap, inFlight)
			mu.Unlock()
			defer func() {
				mu.Lock()
				inFlight--
				mu.Unlock()
			}()
			time.Sleep(5 * time.Millisecond)
			var hosts []nmap.Host
			for _, a := range addrs {
				if live[a] {
					hosts = append(hosts, nmap.Host{Address: a, Up: true})
				}
			}
			return hosts, ctx.Err()
		},
		ServicesFunc: func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
			hosts := make([]nmap.Host, len(addrs))
			for i, a := range addrs {
				p := nmap.Port{Number: 22, Protocol: "tcp", State: "open", Service: "ssh"}
				if netip.MustParseAddr(a).As4()[3]%2 == 0 {
					p = nmap.Port{Number: 80, Protocol: "tcp", State: "open", Service: "http"}
				}
				hosts[i] = nmap.Host{Address: a, Up: true, Ports: []nmap.Port{p}}
			}
			return hosts, nil
		},
	}
	clock := scantest.NewClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	tr := &scantest.Transport{Clock: clock}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: include, Ports: []int{22, 80}, MaxRate: 1000, Workers: 16}

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	var peak atomic.Uint64
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > base && m.HeapAlloc-base > peak.Load() {
				peak.Store(m.HeapAlloc - base)
			}
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
	err = (&scan.Scanner{Store: st, Runner: r, Clock: clock, Transport: tr.For}).Run(context.Background(), testRun(settings))
	close(stop)
	<-sampled
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if s := st.Statuses(); s[len(s)-1] != inventory.RunCompleted {
		t.Fatalf("statuses = %v, want completed", s)
	}
	if st.AddressTotal() != len(all) {
		t.Fatalf("address total = %d, want %d", st.AddressTotal(), len(all))
	}

	covered := map[string]int{}
	var sizes []int
	recorded := map[string]int{}
	for _, g := range st.Groups() {
		sizes = append(sizes, len(g.Addresses))
		for _, a := range g.Addresses {
			covered[a]++
		}
		for _, h := range g.Hosts {
			recorded[h.Address]++
		}
	}
	for _, l := range st.Late() {
		for _, h := range l {
			recorded[h.Address]++
		}
	}
	for _, a := range all {
		if covered[a] != 1 {
			t.Fatalf("address %s is in %d groups, want 1", a, covered[a])
		}
	}
	if len(covered) != len(all) {
		t.Fatalf("groups cover %d addresses, want %d", len(covered), len(all))
	}
	for a := range live {
		if recorded[a] != 1 {
			t.Fatalf("live host %s recorded %d times, want 1", a, recorded[a])
		}
	}
	if len(recorded) != len(live) {
		t.Fatalf("recorded %d hosts, want %d live", len(recorded), len(live))
	}
	return largeResult{addresses: len(all), live: len(live), peakHeap: peak.Load(), peakNmap: peakNmap, groupSizes: sizes}
}

// REQ-SCAN-001
func TestLargeRange16384(t *testing.T) {
	res := scanLarge(t)
	if res.addresses != 16384 {
		t.Fatalf("scanned %d addresses, want 16384", res.addresses)
	}
	if res.live < 16384*3/100 || res.live > 16384*4/100 {
		t.Fatalf("live hosts = %d, want about 3%%", res.live)
	}
	if limit := uint64(200 << 20); res.peakHeap >= limit {
		t.Fatalf("heap grew by %d MiB, want < 200 MiB", res.peakHeap>>20)
	}
	if res.peakNmap > 16 {
		t.Fatalf("%d nmap calls in flight, want <= 16 workers", res.peakNmap)
	}
	if res.groupSizes[0] != scan.InitialGroupSize {
		t.Fatalf("first group has %d addresses, want %d", res.groupSizes[0], scan.InitialGroupSize)
	}
	for _, n := range res.groupSizes {
		if n > scan.MaxGroupSize {
			t.Fatalf("group of %d addresses, want <= %d", n, scan.MaxGroupSize)
		}
	}
	t.Logf("%d addresses, %d live, %d groups, heap growth %d MiB, %d nmap calls in flight",
		res.addresses, res.live, len(res.groupSizes), res.peakHeap>>20, res.peakNmap)
}

func BenchmarkLargeRange16384(b *testing.B) {
	for b.Loop() {
		scanLarge(b)
	}
}

// REQ-SCAN-001
func TestGroupSizeAdaptsDuringRun(t *testing.T) {
	clock := scantest.NewClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	r := &nmaptest.Runner{DiscoverFunc: func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
		<-clock.After(time.Duration(len(addrs)) * 100 * time.Millisecond)
		return nil, nil
	}}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.8.0.0/21"}, Ports: []int{80}, MaxRate: 100, Workers: 1}
	if err := (&scan.Scanner{Store: st, Runner: r, Clock: clock}).Run(context.Background(), testRun(settings)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	g := st.Groups()
	if len(g) < 4 || len(g[0].Addresses) != 64 || len(g[1].Addresses) != 64 || len(g[2].Addresses) != 450 || len(g[3].Addresses) != 450 {
		t.Fatalf("group sizes = %d, %d, %d, %d; want 64, 64 (dispatched before the first measurement), then 450 (45 s at 0.1 s per address)",
			len(g[0].Addresses), len(g[1].Addresses), len(g[2].Addresses), len(g[3].Addresses))
	}
	if g[2].Duration != 45*time.Second {
		t.Fatalf("adapted group took %s, want 45s", g[2].Duration)
	}
}

// REQ-SCAN-007
func TestSlowStoreBlocksWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var blocked, discovers atomic.Int32
		st := &scantest.Store{OnRecordGroup: func(inventory.GroupResult) error {
			blocked.Add(1)
			<-release
			return nil
		}}
		r := &nmaptest.Runner{DiscoverFunc: func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			discovers.Add(1)
			return []nmap.Host{{Address: addrs[0], Up: true}}, nil
		}, ServicesFunc: openPorts(22)}
		clock := scantest.NewClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		tr := &scantest.Transport{Clock: clock}
		settings := inventory.RunSettings{Targets: []string{"10.9.0.0/24"}, Ports: []int{22}, MaxRate: 100, Workers: 4, GroupSize: 4}
		done := make(chan error, 1)
		go func() {
			done <- (&scan.Scanner{Store: st, Runner: r, Clock: clock, Transport: tr.For}).Run(context.Background(), testRun(settings))
		}()
		synctest.Wait()
		if n := blocked.Load(); n != 4 {
			t.Fatalf("%d RecordGroup calls while the store is stalled, want 4", n)
		}
		if n := discovers.Load(); n != 4 {
			t.Fatalf("%d groups scanned while the store blocked 4 workers, want 4", n)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		if n := len(st.Groups()); n != 64 {
			t.Fatalf("recorded %d groups, want 64", n)
		}
	})
}

func timeoutRunner(timesOut func(addrs []string) bool) *nmaptest.Runner {
	return &nmaptest.Runner{DiscoverFunc: func(ctx context.Context, addrs []string, opts nmap.Options) ([]nmap.Host, error) {
		if timesOut(addrs) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return allUp(ctx, addrs, opts)
	}}
}

// REQ-SCAN-008
func TestTimedOutGroupSplitsAndFails(t *testing.T) {
	r := timeoutRunner(func(addrs []string) bool { return slices.Contains(addrs, "10.7.0.3") })
	st := &scantest.Store{Prev: []string{"10.7.0.2", "10.7.0.3", "10.7.0.20"}}
	settings := inventory.RunSettings{Targets: []string{"10.7.0.1-16"}, Ports: []int{80}, MaxRate: 100, Workers: 1, GroupSize: 8}
	err := (&scan.Scanner{Store: st, Runner: r, GroupTimeout: 50 * time.Millisecond}).Run(context.Background(), testRun(settings))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if s := st.Statuses(); s[len(s)-1] != inventory.RunCompleted {
		t.Fatalf("statuses = %v, want completed", s)
	}
	failed, _ := st.FailedGroups(context.Background(), 1)
	if len(failed) != 1 || !slices.Equal(failed[0].Addresses, []string{"10.7.0.1", "10.7.0.2", "10.7.0.3", "10.7.0.4"}) ||
		failed[0].Reason == "" {
		t.Fatalf("failed groups = %+v, want one with 10.7.0.1-4 and a reason", failed)
	}
	var covered []string
	indexes := map[int]bool{failed[0].Index: true}
	for _, g := range st.Groups() {
		if indexes[g.Index] {
			t.Fatalf("group index %d used twice", g.Index)
		}
		indexes[g.Index] = true
		covered = append(covered, g.Addresses...)
	}
	slices.SortFunc(covered, func(a, b string) int { return netip.MustParseAddr(a).Compare(netip.MustParseAddr(b)) })
	if want := expand(t, []string{"10.7.0.5-16"}, nil); !slices.Equal(covered, want) {
		t.Fatalf("recorded groups cover %v, want %v", covered, want)
	}
	var withBad int
	for _, c := range r.Calls() {
		if slices.Contains(c.Addrs, "10.7.0.3") {
			withBad++
		}
		if c.Method == "Discover" && slices.Contains(c.Addrs, "10.7.0.2") && len(c.Addrs) < 4 {
			t.Fatalf("failed address re-probed: %v", c.Addrs)
		}
	}
	if withBad != 2 {
		t.Fatalf("10.7.0.3 was scanned %d times, want 2 (group, then its half)", withBad)
	}
	if len(st.Late()) != 0 {
		t.Fatalf("late hosts %v, want none (10.7.0.20 is not a target, failed addresses are not re-probed)", st.Late())
	}
}

// REQ-SCAN-008
func TestTimedOutGroupRecoversAfterSplit(t *testing.T) {
	var calls atomic.Int32
	r := timeoutRunner(func([]string) bool { return calls.Add(1) == 1 })
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.7.1.1-8"}, Ports: []int{80}, MaxRate: 100, Workers: 1, GroupSize: 8}
	if err := (&scan.Scanner{Store: st, Runner: r, GroupTimeout: 50 * time.Millisecond}).Run(context.Background(), testRun(settings)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	failed, _ := st.FailedGroups(context.Background(), 1)
	g := st.Groups()
	if len(failed) != 0 || len(g) != 2 || len(g[0].Addresses) != 4 || len(g[1].Addresses) != 4 {
		t.Fatalf("failed %+v, groups %+v; want no failure and two halves of 4", failed, g)
	}

	calls.Store(0)
	r = timeoutRunner(func([]string) bool { return true })
	st = &scantest.Store{}
	settings = inventory.RunSettings{Targets: []string{"10.7.2.1"}, Ports: []int{80}, MaxRate: 100, Workers: 1, GroupSize: 1}
	if err := (&scan.Scanner{Store: st, Runner: r, GroupTimeout: 20 * time.Millisecond}).Run(context.Background(), testRun(settings)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	failed, _ = st.FailedGroups(context.Background(), 1)
	if len(failed) != 1 || len(r.Calls()) != 2 || len(st.Groups()) != 0 {
		t.Fatalf("single address: failed %+v after %d calls; want failed after one retry", failed, len(r.Calls()))
	}
}

// REQ-SCAN-004 REQ-SCAN-008
func TestResumeSkipsFailedGroups(t *testing.T) {
	st := &scantest.Store{}
	if err := st.RecordFailedGroup(context.Background(), 1, inventory.FailedGroup{Index: 3, Addresses: []string{"10.7.3.1", "10.7.3.2"}, Reason: "timeout"}); err != nil {
		t.Fatal(err)
	}
	r := &nmaptest.Runner{DiscoverFunc: allUp}
	run := testRun(inventory.RunSettings{Targets: []string{"10.7.3.1-4"}, Ports: []int{80}, MaxRate: 100, Workers: 1, GroupSize: 4})
	run.Status = inventory.RunPaused
	if err := (&scan.Scanner{Store: st, Runner: r}).Run(context.Background(), run); err != nil {
		t.Fatalf("Run: %v", err)
	}
	g := st.Groups()
	if len(g) != 1 || g[0].Index != 4 || !slices.Equal(g[0].Addresses, []string{"10.7.3.3", "10.7.3.4"}) {
		t.Fatalf("groups after resume = %+v, want index 4 with 10.7.3.3-4", g)
	}
}
