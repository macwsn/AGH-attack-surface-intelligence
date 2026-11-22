//go:build integration

package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/schedule"
)

// REQ-SCAN-021: AC3 of T-803xb7cwjk
func TestPreviewIgnoresRecheckSpeed(t *testing.T) {
	inv, sched, h, fa := truthSite(t)
	ctx := context.Background()
	d, err := sched.Store.CreateDefinition(ctx, auth.Actor{Username: "test", Addr: "local"}, schedule.Definition{
		Name: "big", InactiveAfter: 3,
		Settings: inventory.RunSettings{Targets: []string{"10.0.0.0/18"}, Ports: []int{22, 80, 443, 3389, 8080, 8443}, MaxRate: 1000, Workers: 4},
		Schedule: schedule.Schedule{Timezone: "UTC", Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily}},
	})
	if err != nil {
		t.Fatal(err)
	}
	record := func(run schedule.Run, addrs []string, hosts []inventory.HostResult, took time.Duration) {
		t.Helper()
		if err := inv.SetRunTotal(ctx, run.ID, len(addrs)); err != nil {
			t.Fatal(err)
		}
		if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: addrs, Hosts: hosts, Duration: took}); err != nil {
			t.Fatal(err)
		}
		if err := inv.SetRunStatus(ctx, run.ID, inventory.RunCompleted); err != nil {
			t.Fatal(err)
		}
	}
	var addrs []string
	for i := range 256 {
		addrs = append(addrs, "10.0.0."+strconv.Itoa(i))
	}
	live := []inventory.HostResult{{Address: "10.0.0.1", Services: []inventory.ServiceResult{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}}}
	full, err := sched.Store.StartRun(ctx, d.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	record(full, addrs, live, 8*time.Second)
	recheck, err := sched.Store.StartRunMode(ctx, d.ID, time.Now(), inventory.ModeRecheck, []string{"10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	record(recheck, []string{"10.0.0.1"}, live, 2*time.Minute)

	rec := do(h, http.MethodGet, "/scans/"+strconv.FormatInt(d.ID, 10)+"/preview", nil, fa.session(t, "alice"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d:\n%s", rec.Code, body)
	}
	if !strings.Contains(body, `from run <a class="addr" href="/runs/`+strconv.FormatInt(full.ID, 10)+`">`) {
		t.Errorf("preview does not take its measured speed from the full run %s but from the newer recheck %s:\n%s", full.Name, recheck.Name, body)
	}
	if strings.Contains(body, " h</span>") || !strings.Contains(body, " min</span><span class=\"label\">Estimated duration</span>") {
		t.Errorf("preview estimates hours or no minutes after a slow recheck:\n%s", body)
	}
}

// REQ-SCAN-009: AC3 of T-803xb7cwjk
func TestRunPageEstimatesBeforeFirstGroup(t *testing.T) {
	inv, sched, h, fa := truthSite(t)
	ctx := context.Background()
	d, err := sched.Store.CreateDefinition(ctx, auth.Actor{Username: "test", Addr: "local"}, schedule.Definition{
		Name: "big", InactiveAfter: 3,
		Settings: inventory.RunSettings{Targets: []string{"10.0.0.0/18"}, Ports: []int{22, 80, 443, 3389, 8080, 8443}, MaxRate: 1000, Workers: 4},
		Schedule: schedule.Schedule{Timezone: "UTC", Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily}},
	})
	if err != nil {
		t.Fatal(err)
	}
	page := func(run schedule.Run) string {
		t.Helper()
		if err := inv.SetRunTotal(ctx, run.ID, 16382); err != nil {
			t.Fatal(err)
		}
		return do(h, http.MethodGet, "/runs/"+strconv.FormatInt(run.ID, 10), nil, fa.session(t, "alice")).Body.String()
	}
	first, err := sched.Store.StartRun(ctx, d.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body := page(first)
	if !strings.Contains(body, "Estimate: about 2-11 min left, from the plan, assuming 5% of addresses are live.") {
		t.Errorf("first run without groups shows no model estimate:\n%s", body)
	}
	var addrs []string
	for i := range 256 {
		addrs = append(addrs, "10.0.0."+strconv.Itoa(i))
	}
	if err := inv.RecordGroup(ctx, first.ID, inventory.GroupResult{Index: 0, Addresses: addrs, Hosts: []inventory.HostResult{}, Duration: 8 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := inv.SetRunStatus(ctx, first.ID, inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
	second, err := sched.Store.StartRun(ctx, d.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body = page(second)
	if !strings.Contains(body, "left, from the speed of run "+first.Name+".") || !strings.Contains(body, "Estimate: about") {
		t.Errorf("second run without groups does not estimate from run %s:\n%s", first.Name, body)
	}
}
