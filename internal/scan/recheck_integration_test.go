//go:build integration

package scan_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"asi/internal/diff"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

type lanScan struct {
	runner *nmaptest.Runner
	tr     *scantest.Transport
	run    inventory.Run
	err    error
}

func scanLAN(t *testing.T, inv *inventory.Inventory, lan *fakeLAN, name string, settings inventory.RunSettings) lanScan {
	t.Helper()
	ctx := context.Background()
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name, InactiveAfter: 3, Settings: settings})
	if err != nil {
		t.Fatalf("CreateRun %s: %v", name, err)
	}
	r := lan.runner()
	tr := &scantest.Transport{Handler: http.HandlerFunc(lan.handler)}
	err = (&scan.Scanner{Store: inv, Runner: r, Transport: tr.For}).Run(ctx, run)
	if got, gerr := inv.RunByName(ctx, name); gerr == nil {
		run = got
	}
	return lanScan{runner: r, tr: tr, run: run, err: err}
}

func mustScanLAN(t *testing.T, inv *inventory.Inventory, lan *fakeLAN, name string, settings inventory.RunSettings) lanScan {
	t.Helper()
	s := scanLAN(t, inv, lan, name, settings)
	if s.err != nil {
		t.Fatalf("scan %s: %v", name, s.err)
	}
	if want := sentPackets(s.runner.Calls(), s.tr.Requests()); s.run.Packets != want || want == 0 {
		t.Fatalf("run %s stored %d packets, sent %d", name, s.run.Packets, want)
	}
	return s
}

func changesFor(d diff.Diff, addr string) []diff.Change {
	var out []diff.Change
	for _, c := range d.Changes {
		if c.Address == addr {
			out = append(out, c)
		}
	}
	return out
}

// REQ-SCAN-016
func TestRecheckWithoutEarlierRun(t *testing.T) {
	inv := openInventory(t)
	lan := &fakeLAN{open: map[string][]int{"10.9.2.5": {80}}, titles: map[string]string{}}
	s := scanLAN(t, inv, lan, "r1", inventory.RunSettings{Targets: []string{"10.9.2.0/28"}, Ports: []int{80}, MaxRate: 1000, Mode: inventory.ModeRecheck})
	if s.err == nil || !strings.Contains(s.err.Error(), "no earlier run to recheck") || !errors.Is(s.err, inventory.ErrNoRecheckBase) {
		t.Fatalf("err = %v, want no earlier run to recheck", s.err)
	}
	if n := len(s.runner.Calls()); n != 0 {
		t.Fatalf("%d nmap calls, want 0", n)
	}
}

// REQ-SCAN-016
func TestRecheckCoverage(t *testing.T) {
	ctx := context.Background()
	inv := openInventory(t)
	a, b := "10.9.0.5", "10.9.0.6"
	lan := &fakeLAN{open: map[string][]int{a: {80}, b: {22}}, titles: map[string]string{a: "a"}}
	settings := inventory.RunSettings{Targets: []string{"10.9.0.0/28"}, Ports: []int{22, 80}, MaxRate: 1000, Workers: 2}
	mustScanLAN(t, inv, lan, "r1", settings)

	only80 := settings
	only80.Ports, only80.Mode = []int{80}, inventory.ModeRecheck
	r2 := mustScanLAN(t, inv, lan, "r2", only80)
	for _, c := range r2.runner.Calls() {
		if len(c.Addrs) != 1 || c.Addrs[0] != a {
			t.Fatalf("recheck with --ports 80 called %s on %v", c.Method, c.Addrs)
		}
	}
	e1, e2 := exportAsOf(t, inv, "r1"), exportAsOf(t, inv, "r2")
	if len(e2.Hosts) != 2 {
		t.Fatalf("export r2 hosts %+v", e2.Hosts)
	}
	h1, h2 := hostOf(t, e1, b), hostOf(t, e2, b)
	if h1.Status != h2.Status || h1.MissedRuns != h2.MissedRuns || h1.Stability != h2.Stability ||
		h2.Services[0].Status != h1.Services[0].Status || h2.Services[0].MissedRuns != h1.Services[0].MissedRuns {
		t.Fatalf("uncontacted host changed: r1 %+v, r2 %+v", h1, h2)
	}
	if d := diff.Compute(e1, e2, diff.Options{}); len(d.Changes) != 0 {
		t.Fatalf("diff r1 -> r2 = %+v, want no change", d.Changes)
	}

	lan.mu.Lock()
	delete(lan.open, a)
	lan.mu.Unlock()
	recheck := settings
	recheck.Mode = inventory.ModeRecheck
	mustScanLAN(t, inv, lan, "r3", recheck)
	e3 := exportAsOf(t, inv, "r3")
	if h := hostOf(t, e3, a); h.Status != inventory.StatusUnstable || h.MissedRuns != 1 {
		t.Fatalf("known host down in recheck: %+v, want unstable missed 1", h)
	}
	if h := hostOf(t, e3, b); h.Status != inventory.StatusActive || h.MissedRuns != 0 {
		t.Fatalf("host b: %+v", h)
	}
	d := diff.Compute(e2, e3, diff.Options{})
	if want := []diff.Change{{Type: diff.HostMissing, Address: a}}; !reflect.DeepEqual(d.Changes, want) {
		t.Fatalf("diff r2 -> r3 = %+v, want %+v", d.Changes, want)
	}
	run, err := inv.RunByName(ctx, "r3")
	if err != nil || run.Settings.RunMode() != inventory.ModeRecheck {
		t.Fatalf("r3 = %+v, %v", run, err)
	}
}

// REQ-SCAN-017
func TestRecheckReportsServiceChanges(t *testing.T) {
	inv := openInventory(t)
	x, y, z := "10.9.1.5", "10.9.1.6", "10.9.1.7"
	lan := &fakeLAN{open: map[string][]int{x: {80}, y: {80}, z: {80}}, titles: map[string]string{x: "v1", y: "y", z: "z"}}
	settings := inventory.RunSettings{Targets: []string{"10.9.1.0/28"}, Ports: []int{22, 80}, MaxRate: 1000, Workers: 2}
	mustScanLAN(t, inv, lan, "r0", settings)
	lan.set(z)
	mustScanLAN(t, inv, lan, "r1", settings)
	e1 := exportAsOf(t, inv, "r1")
	if s := hostOf(t, e1, z).Services; len(s) != 1 || s[0].Status != inventory.StatusUnstable || s[0].MissedRuns != 1 {
		t.Fatalf("z:80 before the recheck: %+v, want unstable", s)
	}

	lan.set(y)
	lan.set(z, 80)
	lan.mu.Lock()
	lan.titles[x] = "v2"
	lan.mu.Unlock()
	recheck := settings
	recheck.Mode = inventory.ModeRecheck
	r2 := mustScanLAN(t, inv, lan, "r2", recheck)
	for _, c := range r2.runner.Calls() {
		if c.Method == "Services" && !reflect.DeepEqual(c.Ports, []int{80}) {
			t.Fatalf("recheck services call on ports %v", c.Ports)
		}
	}
	d := diff.Compute(e1, exportAsOf(t, inv, "r2"), diff.Options{})
	port := 80
	want := []diff.Change{
		{Type: diff.ServiceChanged, Address: x, Port: &port, Protocol: "tcp", Fields: []diff.FieldChange{{Field: "http.title", Old: "v1", New: "v2"}}},
		{Type: diff.ServiceMissing, Address: y, Port: &port, Protocol: "tcp"},
		{Type: diff.ServiceReturned, Address: z, Port: &port, Protocol: "tcp"},
	}
	if fmt.Sprintf("%+v", deref(d.Changes)) != fmt.Sprintf("%+v", deref(want)) {
		t.Fatalf("diff r1 -> r2 =\n%+v\nwant\n%+v", deref(d.Changes), deref(want))
	}
}

type flatChange struct {
	Type, Address, Protocol string
	Port                    int
	Fields                  []diff.FieldChange
	Note                    string
}

func deref(cs []diff.Change) []flatChange {
	out := make([]flatChange, len(cs))
	for i, c := range cs {
		out[i] = flatChange{Type: c.Type, Address: c.Address, Protocol: c.Protocol, Fields: c.Fields, Note: c.Note}
		if c.Port != nil {
			out[i].Port = *c.Port
		}
	}
	return out
}
