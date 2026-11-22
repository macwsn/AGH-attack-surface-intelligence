//go:build integration

package main

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
)

// REQ-SCAN-009
func TestScanShowProgress(t *testing.T) {
	ctx := context.Background()
	c := newCLIEnv(t, "192.0.2.0/28", "")
	run, err := c.inv.CreateRun(ctx, inventory.RunSpec{Name: "slow", Settings: inventory.RunSettings{
		Targets: []string{"10.40.0.0/22"}, Ports: []int{80}, MaxRate: 10, Workers: 2,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.inv.SetRunTotal(ctx, run.ID, 1000); err != nil {
		t.Fatal(err)
	}
	g0 := inventory.GroupResult{Index: 0, Duration: 32 * time.Second}
	for i := range 64 {
		g0.Addresses = append(g0.Addresses, "10.40.0."+strconv.Itoa(i+1))
	}
	g1 := inventory.GroupResult{Index: 1, Duration: 50 * time.Second}
	for i := range 100 {
		g1.Addresses = append(g1.Addresses, "10.40.1."+strconv.Itoa(i+1))
	}
	for _, g := range []inventory.GroupResult{g0, g1} {
		if err := c.inv.RecordGroup(ctx, run.ID, g); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.inv.RecordFailedGroup(ctx, run.ID, inventory.FailedGroup{Index: 2, Addresses: []string{"10.40.2.1", "10.40.2.2"}, Reason: "group 2: discover: context deadline exceeded"}); err != nil {
		t.Fatal(err)
	}
	if err := c.inv.SetRunStatus(ctx, run.ID, inventory.RunPaused); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSuffix(c.mustRun("scan", "show", "slow"), "\n"), "\n")
	if !strings.HasPrefix(lines[0], "run slow status=paused ") ||
		!strings.HasSuffix(lines[0], " groups=2 addresses=164 hosts=0 rate=4.0/s groups_done=2/12 failed_groups=1 eta=3m29s") {
		t.Fatalf("first line %q", lines[0])
	}
	if want := `failed_group=2 addresses=2 reason="group 2: discover: context deadline exceeded"`; lines[len(lines)-1] != want {
		t.Fatalf("last line %q, want %q", lines[len(lines)-1], want)
	}

	c.net.up("192.0.2.3", 80)
	c.scan("fast", "--workers", "2")
	first, groups := showRun(t, c, "fast")
	m := regexp.MustCompile(` rate=\d+\.\d/s groups_done=(\d+)/(\d+) failed_groups=0 eta=0s$`).FindStringSubmatch(first)
	if m == nil || m[1] != m[2] || m[1] != strconv.Itoa(len(groups)) {
		t.Fatalf("completed run first line %q (%d groups)", first, len(groups))
	}
}

// REQ-SCAN-018, REQ-SCAN-020, REQ-SCAN-021
func TestScanPlanAndRate(t *testing.T) {
	ctx := context.Background()
	c := newCLIEnv(t, "192.0.2.0/28", "192.0.2.5")
	c.net.up("192.0.2.1", 80)
	planArgs := []string{"scan", "plan", "--targets-file", c.targets, "--exclude-file", c.excludes, "--ports", "22,80", "--max-rate", "40"}
	r := c.net.runner()
	code, stdout, stderr := c.runCtx(ctx, r, planArgs...)
	if code != 0 {
		t.Fatalf("scan plan: exit %d, stderr %q", code, stderr)
	}
	if want := "plan addresses=13 ports=22,80 groups=1 group_size=64 packets=338 requests=2236 max_rate=40 adaptive=true duration_at_max_rate=1m52s measured_run=- measured_rate=- duration_measured=-\n"; !strings.HasPrefix(stdout, want) {
		t.Fatalf("scan plan before any run:\n%s\nwant prefix %q", stdout, want)
	}
	if calls := r.Calls(); len(calls) != 0 || countRuns(t, c.st) != 0 {
		t.Fatalf("scan plan sent nmap calls %v or created runs (%d)", calls, countRuns(t, c.st))
	}

	c.scan("polite", "--max-rate", "40")
	c.scan("fixed", "--max-rate", "40", "--no-adaptive")
	run, err := c.inv.RunByName(ctx, "fixed")
	if err != nil || !run.Settings.NoAdaptive {
		t.Fatalf("--no-adaptive run settings = %+v, %v", run.Settings, err)
	}
	if run, err := c.inv.RunByName(ctx, "polite"); err != nil || run.Settings.NoAdaptive {
		t.Fatalf("default run settings = %+v, %v; want adaptive on", run.Settings, err)
	}
	out := c.mustRun(planArgs...)
	m := regexp.MustCompile(` measured_run=fixed measured_rate=(\d+\.\d)/s duration_measured=(\S+)\n`).FindStringSubmatch(out)
	if m == nil || m[1] == "0.0" {
		t.Fatalf("scan plan after runs:\n%s", out)
	}
	for name, adaptive := range map[string]string{"polite": "true", "fixed": "false"} {
		first, _ := showRun(t, c, name)
		re := regexp.MustCompile(` max_rate=40 adaptive=` + adaptive + ` actual_peak=(\d+\.\d)/s actual_avg=(\d+\.\d)/s actual_chart=(\S+) limit_chart=(\S+) groups=`)
		m := re.FindStringSubmatch(first)
		if m == nil || m[3] == "-" || m[4] == "-" {
			t.Fatalf("%s first line %q", name, first)
		}
		if peak, _ := strconv.ParseFloat(m[1], 64); peak > 40 {
			t.Fatalf("%s peak %s/s exceeds max rate 40", name, m[1])
		}
	}
}
