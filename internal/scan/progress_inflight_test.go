package scan_test

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
	"asi/internal/schedule"
)

// REQ-SCAN-009: AC2 of T-803xb7cwjk
func TestProgressCountsAddressesInsideRunningGroup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		st := &scantest.Store{}
		services := openPorts(22)
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: func(ctx context.Context, addrs []string, ports []int, opts nmap.Options) ([]nmap.Host, error) {
			<-release
			return services(ctx, addrs, ports, opts)
		}}
		clock := scantest.NewClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		tr := &scantest.Transport{Clock: clock}
		settings := inventory.RunSettings{Targets: []string{"10.9.0.0/26"}, Ports: []int{22}, MaxRate: 100, Workers: 1, GroupSize: 16}
		done := make(chan error, 1)
		go func() {
			done <- (&scan.Scanner{Store: st, Runner: r, Clock: clock, Transport: tr.For}).Run(context.Background(), testRun(settings))
		}()
		synctest.Wait()
		if n := len(st.Groups()); n != 0 {
			t.Fatalf("%d groups recorded while the first is still running, want 0", n)
		}
		beats := st.InFlight()
		if len(beats) == 0 || beats[len(beats)-1] != 16 {
			t.Fatalf("heartbeat in-flight counts = %v, want the last to be 16 (the discovered addresses of the running group)", beats)
		}
		run := inventory.Run{Status: inventory.RunRunning, AddressTotal: 64, InFlight: beats[len(beats)-1], Settings: settings}
		if p := scan.RunProgress(run, nil, nil); p.AddressesDone != 16 {
			t.Errorf("RunProgress before any group = %+v, want 16 addresses done", p)
		}
		if p := schedule.ProgressOf(64, 1, nil).WithInFlight(run.InFlight); p.Percent != 25 {
			t.Errorf("ProgressOf before any group = %+v, want 25%%", p)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		beats = st.InFlight()
		for _, n := range beats {
			if n < 0 || n > 16 {
				t.Fatalf("heartbeat in-flight counts = %v, want each within one group of 16", beats)
			}
		}
		if n := len(st.Groups()); n != 4 {
			t.Fatalf("recorded %d groups, want 4", n)
		}
	})
}

// REQ-SCAN-009: AC2 of T-803xb7cwjk
func TestRunProgressIgnoresInFlightOfStoppedRun(t *testing.T) {
	run := inventory.Run{Status: inventory.RunPaused, AddressTotal: 64, InFlight: 16}
	if p := scan.RunProgress(run, nil, nil); p.AddressesDone != 0 {
		t.Errorf("paused run progress = %+v, want 0 addresses done (in-flight work was dropped)", p)
	}
	run.Status = inventory.RunRunning
	run.InFlight = 100
	if p := scan.RunProgress(run, nil, nil); p.AddressesDone != 64 {
		t.Errorf("progress = %+v, want in-flight capped at the total of 64", p)
	}
}

// REQ-SCAN-009: AC2 of T-803xb7cwjk
func TestInFlightDoesNotShortenTimeLeft(t *testing.T) {
	groups := []inventory.GroupInfo{{AddressCount: 16, Duration: 16 * time.Second}}
	run := inventory.Run{Status: inventory.RunRunning, AddressTotal: 32, Settings: inventory.RunSettings{Workers: 1}}
	before := scan.RunProgress(run, groups, nil)
	run.InFlight = 16
	p := scan.RunProgress(run, groups, nil)
	if p.AddressesDone != 32 || p.Remaining != before.Remaining || p.Remaining != 16*time.Second || p.GroupsTotal != before.GroupsTotal {
		t.Errorf("with 16 in flight: %+v, want 32 done but the time left (%s) and groups total (%d) of the recorded groups", p, before.Remaining, before.GroupsTotal)
	}
}
