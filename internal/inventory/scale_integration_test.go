//go:build integration

package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
)

// REQ-SCAN-007
func TestRecordGroupIsOneTransaction(t *testing.T) {
	inv, s := openInventory(t)
	ctx := context.Background()
	r := mustRun(t, inv, "batch", 0)
	g := GroupResult{Index: 0}
	for i := range 300 {
		a := fmt.Sprintf("10.30.%d.%d", i/200, i%200+1)
		g.Addresses = append(g.Addresses, a)
		g.Hosts = append(g.Hosts, HostResult{Address: a, Services: []ServiceResult{{Port: 22, State: "open"}, {Port: 80, State: "open"}}})
	}
	done := make(chan error, 1)
	go func() { done <- inv.RecordGroup(ctx, r.ID, g) }()
	seen := map[int]bool{}
	for finished := false; !finished; {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("RecordGroup: %v", err)
			}
			finished = true
		default:
		}
		var hosts, services, coverage int
		if err := s.Pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM host_observations WHERE run_id = $1),
				(SELECT count(*) FROM service_observations WHERE run_id = $1),
				(SELECT count(*) FROM run_group_addresses WHERE run_id = $1)`, r.ID).Scan(&hosts, &services, &coverage); err != nil {
			t.Fatal(err)
		}
		if !(hosts == 0 && services == 0 && coverage == 0) && !(hosts == 300 && services == 600 && coverage == 300) {
			t.Fatalf("reader saw a partial group: %d hosts, %d services, %d addresses", hosts, services, coverage)
		}
		seen[hosts] = true
	}
	if !seen[300] {
		t.Fatal("the recorded group was never visible")
	}
}

// REQ-SCAN-008
func TestFailedGroupsAndAddressTotal(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	r := mustRun(t, inv, "fail", 0)
	if err := inv.SetRunTotal(ctx, r.ID, 16384); err != nil {
		t.Fatal(err)
	}
	if got, err := inv.RunByName(ctx, "fail"); err != nil || got.AddressTotal != 16384 {
		t.Fatalf("RunByName = %+v, %v; want address total 16384", got, err)
	}
	if err := inv.RecordFailedGroup(ctx, r.ID, FailedGroup{Index: 4, Addresses: []string{"10.31.0.2", "::ffff:10.31.0.1"}, Reason: "deadline"}); err != nil {
		t.Fatal(err)
	}
	if err := inv.RecordFailedGroup(ctx, r.ID, FailedGroup{Index: 1, Addresses: []string{"10.31.0.9"}, Reason: "deadline"}); err != nil {
		t.Fatal(err)
	}
	got, err := inv.FailedGroups(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Index != 1 || got[1].Index != 4 || !slices.Equal(got[1].Addresses, []string{"10.31.0.2", "10.31.0.1"}) ||
		got[1].Reason != "deadline" || got[1].FailedAt.IsZero() {
		t.Fatalf("FailedGroups = %+v", got)
	}
	groups, err := inv.RunGroups(ctx, r.ID)
	if err != nil || len(groups) != 0 {
		t.Fatalf("failed groups count as covered: %+v, %v", groups, err)
	}
	if err := inv.RecordFailedGroup(ctx, 999999, FailedGroup{Index: 0}); !errors.Is(err, ErrUnknownRun) {
		t.Fatalf("unknown run: %v", err)
	}
	if err := inv.SetRunTotal(ctx, 999999, 1); !errors.Is(err, ErrUnknownRun) {
		t.Fatalf("unknown run: %v", err)
	}
	if empty, err := inv.FailedGroups(ctx, mustRun(t, inv, "fail2", 0).ID); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("FailedGroups without failures = %v, %v", empty, err)
	}
}
