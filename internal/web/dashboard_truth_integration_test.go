//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/schedule"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func truthSite(t *testing.T) (*inventory.Inventory, *schedule.Scheduler, http.Handler, *fakeAuth) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	inv := inventory.New(st, keys)
	fa := newFakeAuth()
	sched := &schedule.Scheduler{Store: schedule.NewStore(st, keys), Scanner: &scan.Scanner{Store: inv}}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: fa, Scans: sched})
	if err != nil {
		t.Fatal(err)
	}
	return inv, sched, h, fa
}

func truthRun(t *testing.T, inv *inventory.Inventory, name string, source inventory.RunSource, status inventory.RunStatus, addrs []string, hosts []inventory.HostResult) inventory.Run {
	t.Helper()
	ctx := context.Background()
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name, InactiveAfter: 2, Source: source, Settings: inventory.RunSettings{Targets: addrs, Workers: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.SetRunTotal(ctx, run.ID, len(addrs)); err != nil {
		t.Fatal(err)
	}
	if hosts != nil {
		if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: addrs, Hosts: hosts}); err != nil {
			t.Fatal(err)
		}
	}
	if status != inventory.RunRunning {
		if err := inv.SetRunStatus(ctx, run.ID, status); err != nil {
			t.Fatal(err)
		}
	}
	return run
}

// REQ-WEB-009: AC1 of T-803xb7cwjk
func TestDashboardChangesSurviveImportManualEntryAndRunningRun(t *testing.T) {
	inv, _, h, fa := truthSite(t)
	ssh := inventory.ServiceResult{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}
	web := inventory.ServiceResult{Port: 80, Protocol: "tcp", State: "open", Service: "http"}
	all := []string{"10.60.0.1", "10.60.0.2", "10.60.0.3"}
	truthRun(t, inv, "scan-one", inventory.SourceScan, inventory.RunCompleted, all, []inventory.HostResult{
		{Address: "10.60.0.1", Services: []inventory.ServiceResult{ssh}},
	})
	truthRun(t, inv, "scan-two", inventory.SourceScan, inventory.RunCompleted, all, []inventory.HostResult{
		{Address: "10.60.0.1", Services: []inventory.ServiceResult{ssh}},
		{Address: "10.60.0.2", Services: []inventory.ServiceResult{web}},
	})
	truthRun(t, inv, "import-one", inventory.SourceImport, inventory.RunCompleted, []string{"10.60.0.1"}, []inventory.HostResult{
		{Address: "10.60.0.1", Services: []inventory.ServiceResult{ssh}},
	})
	truthRun(t, inv, "manual-one", inventory.SourceManual, inventory.RunCompleted, []string{"10.60.0.2"}, []inventory.HostResult{
		{Address: "10.60.0.2", Services: []inventory.ServiceResult{web}},
	})
	truthRun(t, inv, "scan-three", inventory.SourceScan, inventory.RunRunning, all, nil)

	rec := do(h, http.MethodGet, "/", nil, fa.session(t, "alice"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d:\n%s", rec.Code, body)
	}
	if strings.Contains(body, "No changes since run") || strings.Contains(body, "Changes appear after the second run.") {
		t.Errorf("dashboard change panel is blank after an import, a manual entry and a running run; want the changes of scan-two against scan-one")
	}
	bar := regexp.MustCompile(`<span>New hosts</span><progress class="bar new" max="\d+" value="1"></progress><span class="num">1</span>`)
	if !bar.MatchString(body) {
		t.Errorf("dashboard lacks the new host of scan-two (New hosts = 1)")
	}
	for _, want := range []string{"scan-two", "scan-one", "Latest import", "import-one", "Running now", "scan-three", `href="/changes`} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
	if !strings.Contains(body, `href="/hosts/10.60.0.2"`) {
		t.Errorf("dashboard does not link the changed host 10.60.0.2 to its page")
	}
}

var pollAttr = regexp.MustCompile(`hx-trigger="[^"]*every \d+s`)

// REQ-SCAN-009: AC2 and AC4 of T-803xb7cwjk
func TestRunPagePollsWhileRunningAndShowsZonedTimes(t *testing.T) {
	inv, _, h, fa := truthSite(t)
	addrs := []string{"10.61.0.1", "10.61.0.2"}
	done := truthRun(t, inv, "done-run", inventory.SourceScan, inventory.RunCompleted, addrs, []inventory.HostResult{{Address: "10.61.0.1"}})
	live := truthRun(t, inv, "live-run", inventory.SourceScan, inventory.RunRunning, addrs, nil)

	rec := do(h, http.MethodGet, fmt.Sprintf("/runs/%d", live.ID), nil, fa.session(t, "alice"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET running run = %d:\n%s", rec.Code, body)
	}
	if !pollAttr.MatchString(body) || !strings.Contains(body, "hx-get=") {
		t.Errorf("running run page does not poll itself (no hx-get with hx-trigger=\"every Ns\")")
	}

	rec = do(h, http.MethodGet, "/", nil, fa.session(t, "alice"))
	if !pollAttr.MatchString(rec.Body.String()) {
		t.Errorf("dashboard running-scan line does not poll itself while live-run is running")
	}

	rec = do(h, http.MethodGet, fmt.Sprintf("/runs/%d", done.ID), nil, fa.session(t, "alice"))
	body = rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET finished run = %d:\n%s", rec.Code, body)
	}
	if pollAttr.MatchString(body) {
		t.Errorf("finished run page still polls")
	}
	clock := regexp.MustCompile(`\d{1,2}:\d{2}(:\d{2})?( ([A-Z]{2,5}|[+-]\d{2,4}))?`)
	times := clock.FindAllStringSubmatch(body, -1)
	if len(times) == 0 {
		t.Fatalf("finished run page shows no time of day:\n%s", body)
	}
	for _, m := range times {
		if m[2] == "" {
			t.Errorf("run page shows the bare timestamp %q without a zone abbreviation", m[0])
		}
	}
}

// REQ-SCAN-021: AC3 of T-803xb7cwjk
func TestPlanPreviewEstimatesSlash18InMinutesNotHours(t *testing.T) {
	_, sched, h, fa := truthSite(t)
	d, err := sched.Store.CreateDefinition(context.Background(), auth.Actor{Username: "test", Addr: "local"}, schedule.Definition{
		Name: "big", InactiveAfter: 3,
		Settings: inventory.RunSettings{Targets: []string{"10.0.0.0/18"}, Ports: []int{22, 80, 443, 3389, 8080, 8443}, MaxRate: 1000, Workers: 4},
		Schedule: schedule.Schedule{Timezone: "UTC", Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(h, http.MethodGet, "/scans/"+strconv.FormatInt(d.ID, 10)+"/preview", nil, fa.session(t, "alice"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET preview = %d:\n%s", rec.Code, body)
	}
	if !strings.Contains(strings.ToLower(body), "estimate") {
		t.Errorf("preview does not label its duration as an estimate")
	}
	if regexp.MustCompile(`\d+ h \d+ min`).MatchString(body) {
		t.Errorf("preview estimates hours for a /18 with 6 ports at rate 1000: %v", regexp.MustCompile(`\d+ h \d+ min`).FindAllString(body, -1))
	}
	if !regexp.MustCompile(`about \d+\s*[-\x{2013}]\s*\d+ min`).MatchString(body) {
		t.Errorf("preview does not show the estimate as a range of minutes ('about 2-4 min')")
	}
}
