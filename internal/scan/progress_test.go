package scan_test

import (
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
)

// REQ-SCAN-009
func TestRunProgress(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	groups := []inventory.GroupInfo{
		{Index: 0, AddressCount: 64, Duration: 32 * time.Second, CompletedAt: t0},
		{Index: 1, AddressCount: 100, Duration: 50 * time.Second, CompletedAt: t0.Add(time.Minute)},
	}
	failed := []inventory.FailedGroup{{Index: 2, Addresses: []string{"10.0.0.1", "10.0.0.2"}}}
	run := inventory.Run{Status: inventory.RunRunning, AddressTotal: 1166, Settings: inventory.RunSettings{Workers: 2}}

	p := scan.RunProgress(run, groups, failed)
	if p.AddressesDone != 166 || p.GroupsDone != 2 || p.GroupsFailed != 1 {
		t.Fatalf("progress = %+v, want 166 addresses in 2 done and 1 failed group", p)
	}
	if want := 164.0 / 82 * 2; p.AddressesPerSecond != want {
		t.Fatalf("rate = %v, want %v (2 addresses/s per worker x 2 workers)", p.AddressesPerSecond, want)
	}
	if p.GroupsTotal != 13 {
		t.Fatalf("groups total = %d, want 13 (3 + 1000 left in groups of 100)", p.GroupsTotal)
	}
	if !p.RemainingKnown || p.Remaining != 250*time.Second || p.ETA() != "4m10s" {
		t.Fatalf("remaining = %s known=%v ETA %q, want 4m10s", p.Remaining, p.RemainingKnown, p.ETA())
	}

	run.Status = inventory.RunCompleted
	if p := scan.RunProgress(run, groups, failed); p.Remaining != 0 || p.ETA() != "0s" || p.GroupsTotal != 3 {
		t.Fatalf("completed run progress = %+v", p)
	}

	unknown := scan.RunProgress(inventory.Run{Status: inventory.RunRunning, AddressTotal: 500}, nil, nil)
	if unknown.ETA() != "-" || unknown.AddressesPerSecond != 0 || unknown.GroupsTotal != 8 {
		t.Fatalf("progress without groups = %+v, ETA %q; want unknown ETA and 8 groups of 64", unknown, unknown.ETA())
	}
	if p := scan.RunProgress(inventory.Run{Status: inventory.RunPaused}, groups, nil); p.ETA() != "-" {
		t.Fatalf("run without a stored address total: ETA %q, want -", p.ETA())
	}
}
