//go:build integration

package main

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"asi/internal/inventory"
)

// REQ-SCAN-016
func TestScanRunMode(t *testing.T) {
	ctx := context.Background()
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.7")
	c.net.up("192.0.2.1", 80)
	c.net.up("192.0.2.2", 22)

	r := c.net.runner()
	code, stdout, stderr := c.runCtx(ctx, r, c.scanArgs("re0", "--mode", "recheck")...)
	assertOneLineError(t, "recheck without base", code, stderr, "no earlier run to recheck")
	if stdout != "" || len(r.Calls()) != 0 || countRuns(t, c.st) != 0 {
		t.Fatalf("recheck without base: stdout %q, calls %d, runs %d", stdout, len(r.Calls()), countRuns(t, c.st))
	}

	c.scan("f1")
	c.scan("f2", "--mode", "full")
	f1, err := c.inv.RunByName(ctx, "f1")
	if err != nil {
		t.Fatal(err)
	}
	f2, err := c.inv.RunByName(ctx, "f2")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f1.Settings, f2.Settings) || f1.Settings.RunMode() != inventory.ModeFull || f1.Packets == 0 || f1.Packets != f2.Packets {
		t.Fatalf("default %+v (packets %d) and --mode full %+v (packets %d) differ", f1.Settings, f1.Packets, f2.Settings, f2.Packets)
	}

	r = c.net.runner()
	code, stdout, stderr = c.runCtx(ctx, r, c.scanArgs("re1", "--mode", "recheck")...)
	if code != 0 || !strings.HasPrefix(stdout, "run re1 status=completed ") {
		t.Fatalf("recheck: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	for _, call := range r.Calls() {
		for _, a := range call.Addrs {
			if a != "192.0.2.1" && a != "192.0.2.2" {
				t.Fatalf("recheck %s contacted %s", call.Method, a)
			}
		}
	}
	re1, err := c.inv.RunByName(ctx, "re1")
	if err != nil {
		t.Fatal(err)
	}
	if re1.Settings.Mode != inventory.ModeRecheck || re1.Packets == 0 || re1.Packets*2 > f1.Packets {
		t.Fatalf("recheck run %+v packets %d, full %d", re1.Settings, re1.Packets, f1.Packets)
	}
	for name, want := range map[string]string{
		"f1":  fmt.Sprintf(" mode=full packets=%d ", f1.Packets),
		"re1": fmt.Sprintf(" mode=recheck packets=%d ", re1.Packets),
	} {
		if first, _ := showRun(t, c, name); !strings.Contains(first, want) {
			t.Fatalf("scan show %s: %q does not contain %q", name, first, want)
		}
	}
}

// REQ-SCAN-020 REQ-SCAN-021
func TestScanPlanRecheckAndEstimatedPackets(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.7")
	c.net.up("192.0.2.1", 80)
	c.net.up("192.0.2.2", 22)
	c.scan("f1", "--max-rate", "6", "--workers", "4")

	plan := c.mustRun("scan", "plan", "--targets-file", c.targets, "--exclude-file", c.excludes, "--ports", "22,80", "--mode", "recheck",
		"--max-rate", "6", "--workers", "4")
	for _, want := range []string{
		"plan addresses=2 ports=22,80 groups=1 ",
		"\nplan_mode mode=recheck base_run=f1 services=2 nmap_slots=2 min_rate=4\n",
		"\nrecheck: only the 2 known open services of run f1 are planned",
		"\nlowest rate when backing off: 4/s, because nmap sends at least one packet per second per slot (nmap slots: 2)\n",
	} {
		if !strings.Contains(plan, want) {
			t.Fatalf("scan plan --mode recheck:\n%s\nlacks %q", plan, want)
		}
	}
	full := c.mustRun("scan", "plan", "--targets-file", c.targets, "--exclude-file", c.excludes, "--ports", "22,80", "--max-rate", "6", "--workers", "4")
	if !strings.Contains(full, "plan addresses=6 ") || !strings.Contains(full, "\nplan_mode mode=full base_run=- services=- nmap_slots=3 min_rate=6\n") || strings.Contains(full, "recheck:") {
		t.Fatalf("scan plan full:\n%s", full)
	}

	first, _ := showRun(t, c, "f1")
	m := regexp.MustCompile(` packets=(\d+) requests_measured=(\d+) nmap_packets_estimated=(\d+) max_rate=6 `).FindStringSubmatch(first)
	if m == nil {
		t.Fatalf("scan show f1: %q lacks measured requests and estimated packets", first)
	}
	packets, _ := strconv.Atoi(m[1])
	requests, _ := strconv.Atoi(m[2])
	estimated, _ := strconv.Atoi(m[3])
	if requests == 0 || estimated == 0 || requests+estimated != packets {
		t.Fatalf("scan show f1: packets=%d, requests_measured=%d + nmap_packets_estimated=%d: want one formula", packets, requests, estimated)
	}
}
