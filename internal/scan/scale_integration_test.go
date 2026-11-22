//go:build integration

package scan_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

// REQ-SCAN-008
func TestFailedGroupDoesNotCountHostsAsMissed(t *testing.T) {
	inv := openInventory(t)
	ctx := context.Background()
	include := []string{"10.20.0.1-8"}
	const stuck, other = "10.20.0.2", "10.20.0.6"
	mustScan(t, inv, newNetwork([]string{stuck, other}, nil), "f1", 1, settingsFor(include, nil, 8))

	net := newNetwork([]string{stuck, other}, nil)
	base := net.runner()
	r := &nmaptest.Runner{
		DiscoverFunc: func(ctx context.Context, addrs []string, opts nmap.Options) ([]nmap.Host, error) {
			if slices.Contains(addrs, stuck) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return base.DiscoverFunc(ctx, addrs, opts)
		},
		ServicesFunc: base.ServicesFunc,
	}
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "f2", InactiveAfter: 1, Settings: settingsFor(include, nil, 8)})
	if err != nil {
		t.Fatal(err)
	}
	tr := &scantest.Transport{Handler: net.handler}
	if err := (&scan.Scanner{Store: inv, Runner: r, Transport: tr.For, GroupTimeout: 100 * time.Millisecond}).Run(ctx, run); err != nil {
		t.Fatalf("Run: %v", err)
	}
	failed, err := inv.FailedGroups(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(failed) != 1 || !slices.Equal(failed[0].Addresses, []string{"10.20.0.1", "10.20.0.2", "10.20.0.3", "10.20.0.4"}) ||
		failed[0].Reason == "" || failed[0].FailedAt.IsZero() {
		t.Fatalf("failed groups = %+v, want 10.20.0.1-4 with a reason", failed)
	}
	if run, err = inv.RunByName(ctx, "f2"); err != nil || run.Status != inventory.RunCompleted || run.AddressTotal != 8 {
		t.Fatalf("run = %+v, %v; want completed with 8 addresses", run, err)
	}
	e := exportAsOf(t, inv, "f2")
	if h := hostOf(t, e, stuck); h.Status != inventory.StatusActive || h.MissedRuns != 0 {
		t.Fatalf("host of the failed group = %s missed %d, want active and not missed", h.Status, h.MissedRuns)
	}
	if h := hostOf(t, e, other); h.Status != inventory.StatusActive || h.MissedRuns != 0 {
		t.Fatalf("host of the finished half = %s missed %d", h.Status, h.MissedRuns)
	}
	groups, err := inv.RunGroups(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	p := scan.RunProgress(run, groups, failed)
	if p.GroupsDone != 1 || p.GroupsFailed != 1 || p.GroupsTotal != 2 || p.AddressesDone != 8 || p.ETA() != "0s" {
		t.Fatalf("progress = %+v", p)
	}
}

// REQ-SCAN-007
func TestBoundedPoolLargeScan(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, storetest.DatabaseURL(t)+"&pool_max_conns=2")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	k, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	inv := inventory.New(s, k)

	var up []string
	for i := 0; i < 1024; i += 10 {
		up = append(up, fmt.Sprintf("10.21.%d.%d", i/256, i%256))
	}
	net := newNetwork(up, nil)
	settings := inventory.RunSettings{Targets: []string{"10.21.0.0/22"}, Ports: []int{22, 80}, MaxRate: 1000, Workers: 16, GroupSize: 16}
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "pool", Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	var peak atomic.Int32
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			st := s.Pool.Stat()
			if n := st.TotalConns(); n > peak.Load() {
				peak.Store(n)
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	tr := &scantest.Transport{Handler: net.handler}
	err = (&scan.Scanner{Store: inv, Runner: net.runner(), Transport: tr.For}).Run(ctx, run)
	close(stop)
	<-sampled
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if max := s.Pool.Stat().MaxConns(); max != 2 || peak.Load() > max {
		t.Fatalf("pool max %d, peak connections %d; want at most 2", max, peak.Load())
	}
	if s.Pool.Stat().EmptyAcquireCount() == 0 {
		t.Fatal("no worker ever waited for a connection; the test does not exercise the bound")
	}
	groups, err := inv.RunGroups(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	addrs, hosts := 0, 0
	for _, g := range groups {
		addrs += g.AddressCount
		hosts += g.HostsFound
	}
	if addrs != 1022 || hosts != len(up)-1 {
		t.Fatalf("recorded %d addresses and %d hosts, want 1022 and %d", addrs, hosts, len(up)-1)
	}
}
