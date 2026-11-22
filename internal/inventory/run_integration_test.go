//go:build integration

package inventory

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"asi/internal/detect"
	"asi/internal/probe"
)

func TestCreateRunStoresSettingsAndStatus(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	settings := RunSettings{
		Targets:       []string{"10.0.0.0/28"},
		Excludes:      []string{"10.0.0.1", "10.0.0.5-6"},
		Ports:         []int{80, 443},
		SignaturesDir: "/sig",
		MaxRate:       100,
		Workers:       4,
		GroupSize:     8,
	}
	created, err := inv.CreateRun(ctx, RunSpec{Name: "s1", InactiveAfter: 5, Settings: settings})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if created.Status != RunRunning || created.FinishedAt != nil {
		t.Fatalf("new run: status %q finished %v, want running and nil", created.Status, created.FinishedAt)
	}
	got, err := inv.RunByName(ctx, "s1")
	if err != nil {
		t.Fatalf("RunByName: %v", err)
	}
	if got.ID != created.ID || got.InactiveAfter != 5 || !reflect.DeepEqual(got.Settings, settings) {
		t.Fatalf("RunByName = %+v, want id %d, inactive_after 5, settings %+v", got, created.ID, settings)
	}

	_, err = inv.CreateRun(ctx, RunSpec{Name: "s1"})
	if !errors.Is(err, ErrRunExists) || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate CreateRun error = %v, want ErrRunExists", err)
	}

	_, err = inv.RunByName(ctx, "nope")
	if !errors.Is(err, ErrUnknownRun) || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("RunByName(unknown) error = %v, want ErrUnknownRun naming the run", err)
	}
	latest, err := inv.RunByName(ctx, "")
	if err != nil || latest.Name != "s1" {
		t.Fatalf("RunByName(\"\") = %+v, %v; want s1", latest, err)
	}
}

func TestRunByNameNoRuns(t *testing.T) {
	inv, _ := openInventory(t)
	if _, err := inv.RunByName(context.Background(), ""); !errors.Is(err, ErrUnknownRun) {
		t.Fatalf("RunByName(\"\") on empty inventory error = %v, want ErrUnknownRun", err)
	}
}

func TestSetRunStatus(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	r := mustRun(t, inv, "st", 0)
	for _, tc := range []struct {
		status   RunStatus
		finished bool
	}{
		{RunPaused, false},
		{RunRunning, false},
		{RunFailed, true},
		{RunCompleted, true},
	} {
		if err := inv.SetRunStatus(ctx, r.ID, tc.status); err != nil {
			t.Fatalf("SetRunStatus(%s): %v", tc.status, err)
		}
		got, err := inv.RunByName(ctx, "st")
		if err != nil {
			t.Fatalf("RunByName: %v", err)
		}
		if got.Status != tc.status || (got.FinishedAt != nil) != tc.finished {
			t.Fatalf("after SetRunStatus(%s): status %q finished_at %v", tc.status, got.Status, got.FinishedAt)
		}
	}
	if err := inv.SetRunStatus(ctx, r.ID, "bogus"); err == nil {
		t.Fatal("SetRunStatus(bogus) succeeded")
	}
	if err := inv.SetRunStatus(ctx, r.ID+1000, RunPaused); !errors.Is(err, ErrUnknownRun) {
		t.Fatalf("SetRunStatus(unknown id) error = %v, want ErrUnknownRun", err)
	}
}

func TestRunGroupsTiming(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	r := mustRun(t, inv, "g", 0)
	mustRecord(t, inv, r, GroupResult{Index: 1, Addresses: []string{"10.0.0.3", "10.0.0.4"}, Duration: 2 * time.Second})
	g0 := GroupResult{
		Index:     0,
		Addresses: []string{"10.0.0.1", "10.0.0.2"},
		Hosts:     []HostResult{{Address: "10.0.0.2", Services: []ServiceResult{{Port: 80, State: "open"}}}},
		Duration:  1500 * time.Millisecond,
	}
	mustRecord(t, inv, r, g0)
	mustRecord(t, inv, r, g0)

	groups, err := inv.RunGroups(ctx, r.ID)
	if err != nil {
		t.Fatalf("RunGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("RunGroups returned %d groups, want 2", len(groups))
	}
	want := []GroupInfo{
		{Index: 0, Addresses: []string{"10.0.0.1", "10.0.0.2"}, AddressCount: 2, HostsFound: 1, Duration: 1500 * time.Millisecond},
		{Index: 1, Addresses: []string{"10.0.0.3", "10.0.0.4"}, AddressCount: 2, HostsFound: 0, Duration: 2 * time.Second},
	}
	for i, g := range groups {
		if g.CompletedAt.IsZero() {
			t.Fatalf("group %d has no completion time", g.Index)
		}
		g.CompletedAt = time.Time{}
		if !reflect.DeepEqual(g, want[i]) {
			t.Fatalf("group %d = %+v, want %+v", i, g, want[i])
		}
	}

	if err := inv.RecordGroup(ctx, r.ID, GroupResult{Index: 2, Duration: -time.Second}); err == nil {
		t.Fatal("RecordGroup with a negative duration succeeded")
	}
	empty, err := inv.RunGroups(ctx, mustRun(t, inv, "g2", 0).ID)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("RunGroups of a run without groups = %v, %v; want empty slice", empty, err)
	}
}

func TestPreviouslyLiveAddresses(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	all := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	host := func(a string) HostResult { return HostResult{Address: a} }

	r1 := mustRun(t, inv, "p1", 2)
	if got, err := inv.PreviouslyLiveAddresses(ctx, r1.ID); err != nil || len(got) != 0 {
		t.Fatalf("first run: PreviouslyLiveAddresses = %v, %v; want none", got, err)
	}
	mustRecord(t, inv, r1, GroupResult{Addresses: all, Hosts: []HostResult{host("10.0.0.1"), host("10.0.0.2"), host("10.0.0.3")}})
	r2 := mustRun(t, inv, "p2", 2)
	mustRecord(t, inv, r2, GroupResult{Addresses: all, Hosts: []HostResult{host("10.0.0.1"), host("10.0.0.2")}})
	r3 := mustRun(t, inv, "p3", 2)
	mustRecord(t, inv, r3, GroupResult{Addresses: all, Hosts: []HostResult{host("10.0.0.1")}})
	r4 := mustRun(t, inv, "p4", 2)
	mustRecord(t, inv, r4, GroupResult{Addresses: all})

	got, err := inv.PreviouslyLiveAddresses(ctx, r4.ID)
	if err != nil {
		t.Fatalf("PreviouslyLiveAddresses: %v", err)
	}
	if want := []string{"10.0.0.1", "10.0.0.2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("PreviouslyLiveAddresses as of p3 = %v, want %v (10.0.0.3 is inactive)", got, want)
	}
}

func TestRecordLateHosts(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	r1 := mustRun(t, inv, "l1", 0)
	mustRecord(t, inv, r1, GroupResult{Addresses: []string{"10.0.0.1", "10.0.0.2"},
		Hosts: []HostResult{{Address: "10.0.0.1"}, {Address: "10.0.0.2", Services: []ServiceResult{{Port: 22, State: "open"}}}}})
	r2 := mustRun(t, inv, "l2", 0)
	mustRecord(t, inv, r2, GroupResult{Index: 0, Addresses: []string{"10.0.0.1"}, Duration: time.Second})
	mustRecord(t, inv, r2, GroupResult{Index: 1, Addresses: []string{"10.0.0.2"}, Duration: time.Second})

	late := []HostResult{{Address: "10.0.0.2", Hostnames: []string{"late.example"},
		Services: []ServiceResult{{Port: 22, State: "open", Service: "ssh"}}}}
	if err := inv.RecordLateHosts(ctx, r2.ID, late); err != nil {
		t.Fatalf("RecordLateHosts: %v", err)
	}
	if err := inv.RecordLateHosts(ctx, r2.ID, late); err != nil {
		t.Fatalf("RecordLateHosts again: %v", err)
	}

	e := mustExport(t, inv, "l2")
	h := findHost(t, e, "10.0.0.2")
	if h.Status != StatusActive || h.MissedRuns != 0 || !reflect.DeepEqual(h.Hostnames, []string{"late.example"}) {
		t.Fatalf("late host = %+v, want active, missed 0, hostname late.example", h)
	}
	if s := findService(t, h, 22); s.Status != StatusActive || s.Service != "ssh" {
		t.Fatalf("late service = %+v, want active ssh", s)
	}
	if h := findHost(t, e, "10.0.0.1"); h.Status != StatusUnstable {
		t.Fatalf("missed host status = %s, want unstable", h.Status)
	}

	groups, err := inv.RunGroups(ctx, r2.ID)
	if err != nil {
		t.Fatalf("RunGroups: %v", err)
	}
	if groups[0].HostsFound != 0 || groups[1].HostsFound != 1 || groups[1].Duration != time.Second {
		t.Fatalf("groups after late hosts = %+v, want hosts_found 0 and 1, duration kept", groups)
	}

	if err := inv.RecordLateHosts(ctx, r2.ID, []HostResult{{Address: "10.0.0.9"}}); err == nil {
		t.Fatal("RecordLateHosts for an address outside every recorded group succeeded")
	}
	if err := inv.RecordLateHosts(ctx, r2.ID+1000, late); !errors.Is(err, ErrUnknownRun) {
		t.Fatalf("RecordLateHosts(unknown run) error = %v, want ErrUnknownRun", err)
	}
}

func TestMigrationsKeepExistingRunsCompleted(t *testing.T) {
	_, s := openInventory(t)
	ctx := context.Background()
	var def string
	if err := s.Pool.QueryRow(ctx, `SELECT column_default FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'runs' AND column_name = 'status'`).Scan(&def); err != nil {
		t.Fatalf("read status default: %v", err)
	}
	if !strings.Contains(def, "running") {
		t.Fatalf("runs.status default = %s, want running", def)
	}
	if applied, err := s.Migrate(ctx); err != nil || len(applied) != 0 {
		t.Fatalf("second Migrate = %v, %v; want nothing applied", applied, err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO runs (name, inactive_after, status) VALUES ('bad', 3, 'done')`); err == nil {
		t.Fatal("runs accepted status 'done'")
	}
}

// REQ-INVENTORY-019
func TestCreateRunStoresSource(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	for name, want := range map[string]RunSource{"": SourceScan, "import": SourceImport, "manual": SourceManual} {
		created, err := inv.CreateRun(ctx, RunSpec{Name: "r-" + name, Source: RunSource(name)})
		if err != nil {
			t.Fatalf("CreateRun source %q: %v", name, err)
		}
		got, err := inv.RunByName(ctx, "r-"+name)
		if err != nil || created.Source != want || got.Source != want {
			t.Fatalf("source %q: created %q, read %q (%v), want %q", name, created.Source, got.Source, err, want)
		}
	}
	if _, err := inv.CreateRun(ctx, RunSpec{Name: "bad", Source: "upload"}); err == nil {
		t.Fatal("CreateRun with source upload succeeded")
	}
	if _, err := inv.RunByName(ctx, "bad"); !errors.Is(err, ErrUnknownRun) {
		t.Fatalf("bad run was created: %v", err)
	}
}

// REQ-INVENTORY-010
func TestListRunsNewestFirst(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	if runs, err := inv.ListRuns(ctx); err != nil || len(runs) != 0 {
		t.Fatalf("ListRuns on empty inventory = %v, %v; want none", runs, err)
	}
	a := mustRun(t, inv, "a", 0)
	mustRun(t, inv, "b", 0)
	if err := inv.SetRunStatus(ctx, a.ID, RunCompleted); err != nil {
		t.Fatal(err)
	}
	runs, err := inv.ListRuns(ctx)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 2 || runs[0].Name != "b" || runs[1].Name != "a" || runs[0].Status != RunRunning || runs[1].Status != RunCompleted {
		t.Fatalf("ListRuns = %+v, want b (running) then a (completed)", runs)
	}
}

// REQ-SCAN-020
func TestRateSamplesAccumulatePerMinute(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	run, err := inv.CreateRun(ctx, RunSpec{Name: "r", Settings: RunSettings{MaxRate: 100, NoAdaptive: true}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := inv.RunByName(ctx, "r"); err != nil || !got.Settings.NoAdaptive {
		t.Fatalf("no_adaptive not stored: %+v, %v", got.Settings, err)
	}
	m0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	for _, batch := range [][]RateSample{
		{{Minute: m0, Configured: 100, Effective: 100, Sent: 40}},
		{{Minute: m0.Add(20 * time.Second), Configured: 100, Effective: 50, Sent: 20}, {Minute: m0.Add(time.Minute), Configured: 100, Effective: 25, Sent: 7}},
	} {
		if err := inv.RecordRateSamples(ctx, run.ID, batch); err != nil {
			t.Fatal(err)
		}
	}
	got, err := inv.RateSamples(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []RateSample{{Minute: m0, Configured: 100, Effective: 100, Sent: 60}, {Minute: m0.Add(time.Minute), Configured: 100, Effective: 25, Sent: 7}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("samples = %+v, want %+v", got, want)
	}
	if err := inv.RecordRateSamples(ctx, run.ID+1000, want); !errors.Is(err, ErrUnknownRun) {
		t.Fatalf("unknown run: %v", err)
	}
}

func TestLatestHTTPReturnsTheStoredBody(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	r1 := mustRun(t, inv, "b1", 0)
	mustRecord(t, inv, r1, GroupResult{Addresses: []string{"10.0.0.1"}, Hosts: []HostResult{{Address: "10.0.0.1",
		Services: []ServiceResult{{Port: 80, Protocol: "tcp", State: "open", Service: "http",
			HTTP: &probe.HTTP{Scheme: "http", StatusCode: 200, Title: "Jenkins"}, Body: []byte("<p>Jenkins ver. 2.401</p>")}}}}})
	h, body, run, err := inv.LatestHTTP(ctx, "10.0.0.1", 80, "tcp")
	if err != nil || h == nil || h.Title != "Jenkins" || run != "b1" || string(body) != "<p>Jenkins ver. 2.401</p>" {
		t.Fatalf("LatestHTTP = %+v, %q, %q, %v; want the Jenkins response with its body from run b1", h, body, run, err)
	}
	sig, err := detect.ParseOne([]byte("id: j\nname: Jenkins\nkind: technology\nconfidence: 90\nmatch: {all: [{type: body_regex, value: 'Jenkins ver'}]}\nversion: {type: body_regex, value: 'ver\\. ([0-9.]+)', group: 1}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := sig.EvaluateHistory(h, body); !ok || !e.Matched || e.Version != "2.401" {
		t.Fatalf("body signature on the latest observation = %+v, %t; want a match with version 2.401", e, ok)
	}
}
