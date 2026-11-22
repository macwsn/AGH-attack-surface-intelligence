//go:build integration

package scan_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"asi/internal/diff"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/scantest"
)

func fullScan(t *testing.T, inv *inventory.Inventory, lan *fakeLAN, name string, settings inventory.RunSettings) {
	t.Helper()
	ctx := context.Background()
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name, InactiveAfter: 2, Settings: settings})
	if err != nil {
		t.Fatalf("CreateRun %s: %v", name, err)
	}
	tr := &scantest.Transport{Handler: http.HandlerFunc(lan.handler)}
	s := &scan.Scanner{Store: inv, Runner: lan.runner(), Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := s.Run(ctx, run); err != nil {
		t.Fatalf("scan %s: %v", name, err)
	}
}

// REQ-SCAN-016
func TestFullRunOnFewerPortsLeavesUncoveredServiceAsItWas(t *testing.T) {
	inv := openInventory(t)
	a := "10.9.3.5"
	lan := &fakeLAN{open: map[string][]int{a: {22, 80}}, titles: map[string]string{a: "a"}}
	both := inventory.RunSettings{Targets: []string{"10.9.3.0/28"}, Ports: []int{22, 80}, MaxRate: 1000, Workers: 2}
	fullScan(t, inv, lan, "f1", both)
	e1 := exportAsOf(t, inv, "f1")
	if h := hostOf(t, e1, a); len(h.Services) != 2 {
		t.Fatalf("after full run on 22+80: services %+v, want 22 and 80", h.Services)
	}

	only22 := both
	only22.Ports = []int{22}
	fullScan(t, inv, lan, "f2", only22)
	fullScan(t, inv, lan, "f3", only22)
	e2, e3 := exportAsOf(t, inv, "f2"), exportAsOf(t, inv, "f3")
	for _, e := range []inventory.Export{e2, e3} {
		for _, s := range hostOf(t, e, a).Services {
			if s.Port == 80 && (s.Status != inventory.StatusActive || s.MissedRuns != 0) {
				t.Errorf("run %s: service on port 80 not covered by the run is %s missed %d, want active missed 0 as before",
					e.Run, s.Status, s.MissedRuns)
			}
		}
	}
	for _, d := range []diff.Diff{diff.Compute(e1, e2, diff.Options{}), diff.Compute(e2, e3, diff.Options{})} {
		for _, c := range d.Changes {
			if c.Type == diff.ServiceMissing && c.Port != nil && *c.Port == 80 {
				t.Errorf("diff reports service_missing for port 80 that the full run on port 22 did not cover: %+v", c)
			}
		}
	}
}
