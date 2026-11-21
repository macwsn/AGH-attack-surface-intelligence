//go:build integration

package schedule_test

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
	"asi/internal/schedule"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

type fakeTime struct {
	mu  sync.Mutex
	now time.Time
}

func (f *fakeTime) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeTime) Set(s string) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	f.mu.Lock()
	f.now = t
	f.mu.Unlock()
}

type gatedNmap struct {
	mu      sync.Mutex
	block   bool
	calls   int
	allowed int
	blocked chan struct{}
}

func (g *gatedNmap) runner() *nmaptest.Runner {
	return &nmaptest.Runner{DiscoverFunc: func(ctx context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
		g.mu.Lock()
		g.calls++
		hold := g.block && g.calls > g.allowed
		g.mu.Unlock()
		if hold {
			select {
			case g.blocked <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, nil
	}}
}

func (g *gatedNmap) set(block bool, allowed int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.block, g.calls, g.allowed = block, 0, allowed
}

type env struct {
	db    *store.Store
	inv   *inventory.Inventory
	st    *schedule.Store
	clock *fakeTime
	nmap  *gatedNmap
	run   *nmaptest.Runner
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(db.Close)
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	k, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	g := &gatedNmap{blocked: make(chan struct{}, 1)}
	return &env{db: db, inv: inventory.New(db, k), st: schedule.NewStore(db), clock: &fakeTime{}, nmap: g, run: g.runner()}
}

func (e *env) scheduler(t *testing.T, ctx context.Context) *schedule.Scheduler {
	t.Helper()
	s := &schedule.Scheduler{
		Store:   e.st,
		Scanner: &scan.Scanner{Store: e.inv, Runner: e.run, Clock: scantest.NewClock(time.Unix(0, 0))},
		Now:     e.clock.Now,
		Logf:    t.Logf,
	}
	s.Start(ctx)
	t.Cleanup(s.Wait)
	return s
}

var admin = auth.Actor{Username: "alice", Addr: "192.0.2.1"}

func definition(name string) schedule.Definition {
	return schedule.Definition{
		Name:          name,
		Enabled:       true,
		InactiveAfter: 3,
		Settings: inventory.RunSettings{
			Targets:   []string{"10.0.0.0/28"},
			Excludes:  []string{"10.0.0.14"},
			Ports:     []int{80, 443},
			MaxRate:   50,
			Workers:   1,
			GroupSize: 4,
		},
		Schedule: schedule.Schedule{
			Timezone:  "Europe/Warsaw",
			Windows:   []schedule.Window{{Days: []time.Weekday{1, 2, 3, 4, 5}, Start: "22:00", End: "02:00"}},
			Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily},
		},
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func runsOf(t *testing.T, e *env, defID int64) []schedule.Run {
	t.Helper()
	runs, err := e.st.Runs(context.Background(), defID, 100)
	if err != nil {
		t.Fatalf("Runs: %v", err)
	}
	return runs
}

func status(t *testing.T, e *env, runID int64) inventory.RunStatus {
	t.Helper()
	r, err := e.st.Run(context.Background(), runID)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r.Status
}

func groups(t *testing.T, e *env, runID int64) []inventory.GroupInfo {
	t.Helper()
	g, err := e.inv.RunGroups(context.Background(), runID)
	if err != nil {
		t.Fatalf("RunGroups: %v", err)
	}
	return g
}

func step(t *testing.T, s *schedule.Scheduler) {
	t.Helper()
	if err := s.Step(); err != nil {
		t.Fatalf("Step: %v", err)
	}
}

func discoveredAddrs(r *nmaptest.Runner, from int) []string {
	var out []string
	for _, c := range r.Calls()[from:] {
		if c.Method == "Discover" {
			out = append(out, c.Addrs...)
		}
	}
	return out
}

// REQ-SCHEDULE-001
func TestDefinitionStoresSettingsAndSchedule(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	want := definition("campus")
	want.Settings.SignaturesDir = t.TempDir()
	want.Schedule.Frequency = schedule.Frequency{Kind: schedule.FrequencyInterval, Every: "6h"}
	created, err := e.st.CreateDefinition(ctx, admin, want)
	if err != nil {
		t.Fatalf("CreateDefinition: %v", err)
	}
	got, err := e.st.Definition(ctx, created.ID)
	if err != nil {
		t.Fatalf("Definition: %v", err)
	}
	if got.Name != want.Name || got.InactiveAfter != 3 || !slices.Equal(got.Settings.Targets, want.Settings.Targets) ||
		!slices.Equal(got.Settings.Excludes, want.Settings.Excludes) || !slices.Equal(got.Settings.Ports, want.Settings.Ports) ||
		got.Settings.MaxRate != 50 || got.Settings.Workers != 1 || got.Settings.SignaturesDir != want.Settings.SignaturesDir ||
		got.Schedule.Timezone != "Europe/Warsaw" || got.Schedule.Frequency != want.Schedule.Frequency ||
		len(got.Schedule.Windows) != 1 || schedule.FormatWindows(got.Schedule.Windows) != "mon-fri 22:00-02:00" {
		t.Fatalf("stored definition = %+v, want %+v", got, want)
	}
	if _, err := e.st.CreateDefinition(ctx, admin, want); !errors.Is(err, schedule.ErrDefinitionExists) {
		t.Errorf("duplicate name: err = %v, want ErrDefinitionExists", err)
	}
	bad := definition("bad")
	bad.Settings.Ports = nil
	bad.Schedule.Timezone = "Nowhere/City"
	if _, err := e.st.CreateDefinition(ctx, admin, bad); err == nil || !strings.Contains(err.Error(), "ports") || !strings.Contains(err.Error(), "timezone") {
		t.Errorf("invalid definition: err = %v, want ports and timezone problems", err)
	}
}

// REQ-SCHEDULE-004
func TestSchedulerStopsAtWindowEndAndResumes(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := e.st.CreateDefinition(ctx, admin, definition("night"))
	if err != nil {
		t.Fatal(err)
	}
	s := e.scheduler(t, ctx)

	e.clock.Set("2026-11-16T20:59:00Z")
	step(t, s)
	if runs := runsOf(t, e, d.ID); len(runs) != 0 {
		t.Fatalf("a run started before the window: %+v", runs)
	}

	e.nmap.set(true, 2)
	e.clock.Set("2026-11-16T21:00:00Z")
	step(t, s)
	runs := runsOf(t, e, d.ID)
	if len(runs) != 1 {
		t.Fatalf("runs after the window opened = %d, want 1", len(runs))
	}
	run := runs[0]
	<-e.nmap.blocked
	waitFor(t, "two groups", func() bool { return len(groups(t, e, run.ID)) == 2 })

	e.clock.Set("2026-11-16T22:30:00Z")
	step(t, s)
	if st := status(t, e, run.ID); st != inventory.RunRunning {
		t.Fatalf("status inside the window = %s, want running", st)
	}
	if n := len(runsOf(t, e, d.ID)); n != 1 {
		t.Fatalf("a second run started while one was running: %d runs", n)
	}

	e.clock.Set("2026-11-17T01:00:00Z")
	step(t, s)
	waitFor(t, "paused at window end", func() bool { return status(t, e, run.ID) == inventory.RunPaused })
	done := groups(t, e, run.ID)
	if len(done) != 2 {
		t.Fatalf("groups after the window end = %d, want 2", len(done))
	}
	finished := map[string]bool{}
	for _, g := range done {
		for _, a := range g.Addresses {
			finished[a] = true
		}
	}

	e.nmap.set(false, 0)
	before := len(e.run.Calls())
	e.clock.Set("2026-11-17T12:00:00Z")
	step(t, s)
	time.Sleep(50 * time.Millisecond)
	if st := status(t, e, run.ID); st != inventory.RunPaused {
		t.Fatalf("status outside the window = %s, want paused", st)
	}
	if len(e.run.Calls()) != before {
		t.Fatal("nmap was called outside the window")
	}

	e.clock.Set("2026-11-17T21:00:00Z")
	step(t, s)
	waitFor(t, "completed in the next window", func() bool { return status(t, e, run.ID) == inventory.RunCompleted })
	if n := len(runsOf(t, e, d.ID)); n != 1 {
		t.Fatalf("runs = %d, want the paused run resumed, not a new one", n)
	}
	for _, a := range discoveredAddrs(e.run, before) {
		if finished[a] {
			t.Errorf("address %s of a finished group was scanned again after the resume", a)
		}
	}
	all := groups(t, e, run.ID)
	covered := 0
	for i, g := range all {
		if g.Index != i {
			t.Errorf("group %d has index %d", i, g.Index)
		}
		covered += g.AddressCount
	}
	if covered != 13 {
		t.Errorf("covered addresses = %d, want 13", covered)
	}
	r, _ := e.st.Run(ctx, run.ID)
	if r.AddressTotal != 13 {
		t.Errorf("address total = %d, want 13", r.AddressTotal)
	}
}

// REQ-SCHEDULE-005
func TestOneRunPerDefinition(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := e.st.CreateDefinition(ctx, admin, definition("one"))
	if err != nil {
		t.Fatal(err)
	}
	s := e.scheduler(t, ctx)
	e.nmap.set(true, 0)
	e.clock.Set("2026-11-18T12:00:00Z")
	run, err := s.StartNow(ctx, admin, d.ID)
	if err != nil {
		t.Fatalf("StartNow: %v", err)
	}
	<-e.nmap.blocked
	if _, err := s.StartNow(ctx, admin, d.ID); !errors.Is(err, schedule.ErrRunOpen) {
		t.Errorf("second StartNow: err = %v, want ErrRunOpen", err)
	}
	if _, err := e.st.StartRun(ctx, d.ID, e.clock.Now()); !errors.Is(err, schedule.ErrRunOpen) {
		t.Errorf("second StartRun: err = %v, want ErrRunOpen", err)
	}
	e.clock.Set("2026-11-18T21:30:00Z")
	step(t, s)
	if n := len(runsOf(t, e, d.ID)); n != 1 {
		t.Errorf("runs = %d, want 1", n)
	}

	if err := s.Pause(ctx, admin, run.ID); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if st := status(t, e, run.ID); st != inventory.RunPaused {
		t.Fatalf("status after Pause = %s", st)
	}
	step(t, s)
	time.Sleep(50 * time.Millisecond)
	if st := status(t, e, run.ID); st != inventory.RunPaused {
		t.Fatalf("a run paused by a user was resumed by the scheduler: %s", st)
	}
	if _, err := s.StartNow(ctx, admin, d.ID); !errors.Is(err, schedule.ErrRunOpen) {
		t.Errorf("StartNow with a paused run: err = %v, want ErrRunOpen", err)
	}
	e.nmap.set(false, 0)
	if err := s.Resume(ctx, admin, run.ID); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	waitFor(t, "completed after Resume", func() bool { return status(t, e, run.ID) == inventory.RunCompleted })
	if err := s.Resume(ctx, admin, run.ID); !errors.Is(err, schedule.ErrNotPaused) {
		t.Errorf("Resume of a completed run: err = %v, want ErrNotPaused", err)
	}
	var actions []string
	rows, err := e.db.Pool.Query(ctx, `SELECT action || ' ' || target FROM audit_log WHERE actor = 'alice' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, a)
	}
	want := []string{"scan.create one", "scan.start " + run.Name, "scan.pause " + run.Name, "scan.resume " + run.Name}
	if !slices.Equal(actions, want) {
		t.Errorf("audit = %q, want %q", actions, want)
	}
}

// REQ-SCHEDULE-005
func TestCrashedRunResumesOnStart(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := e.st.CreateDefinition(ctx, admin, definition("crash"))
	if err != nil {
		t.Fatal(err)
	}
	run, err := e.st.StartRun(ctx, d.ID, time.Date(2026, 11, 16, 21, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	crashed := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	if err := e.inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: crashed, Duration: time.Second}); err != nil {
		t.Fatal(err)
	}

	e.clock.Set("2026-11-17T12:00:00Z")
	s := e.scheduler(t, ctx)
	step(t, s)
	if st := status(t, e, run.ID); st != inventory.RunPaused {
		t.Fatalf("status of the interrupted run after the first step = %s, want paused", st)
	}
	if len(e.run.Calls()) != 0 {
		t.Fatal("the interrupted run resumed outside its window")
	}
	e.clock.Set("2026-11-17T21:00:00Z")
	step(t, s)
	waitFor(t, "interrupted run completed", func() bool { return status(t, e, run.ID) == inventory.RunCompleted })
	for _, a := range discoveredAddrs(e.run, 0) {
		if slices.Contains(crashed, a) {
			t.Errorf("address %s of the group finished before the crash was scanned again", a)
		}
	}
	if n := len(runsOf(t, e, d.ID)); n != 1 {
		t.Errorf("runs = %d, want the interrupted run picked up, not a new one", n)
	}
}

// REQ-SCHEDULE-007
func TestEditDuringRunAppliesToNextRun(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := e.st.CreateDefinition(ctx, admin, definition("edit"))
	if err != nil {
		t.Fatal(err)
	}
	s := e.scheduler(t, ctx)
	e.nmap.set(true, 1)
	e.clock.Set("2026-11-18T12:00:00Z")
	run, err := s.StartNow(ctx, admin, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	<-e.nmap.blocked

	edited := d
	edited.Settings.Ports = []int{8080}
	edited.Settings.Targets = []string{"10.0.1.0/30"}
	edited.Schedule.Windows = nil
	if _, err := e.st.UpdateDefinition(ctx, auth.Actor{Username: "bob", Addr: "192.0.2.2"}, edited); err != nil {
		t.Fatalf("UpdateDefinition: %v", err)
	}
	var target string
	if err := e.db.Pool.QueryRow(ctx, `SELECT target FROM audit_log WHERE actor = 'bob' AND action = 'scan.update'`).Scan(&target); err != nil {
		t.Fatalf("audit of the edit: %v", err)
	}
	if target != "edit: targets, ports, windows" {
		t.Errorf("audit target = %q", target)
	}
	open, _ := e.st.Run(ctx, run.ID)
	if !slices.Equal(open.Settings.Ports, []int{80, 443}) || !slices.Equal(open.Settings.Targets, []string{"10.0.0.0/28"}) {
		t.Errorf("open run settings changed by the edit: %+v", open.Settings)
	}

	e.nmap.set(false, 0)
	before := len(e.run.Calls())
	if err := s.Pause(ctx, admin, run.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Resume(ctx, admin, run.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first run completed", func() bool { return status(t, e, run.ID) == inventory.RunCompleted })
	for _, c := range e.run.Calls()[before:] {
		if !slices.Equal(c.Opts.ProbePorts, []int{80, 443}) || slices.ContainsFunc(c.Addrs, func(a string) bool { return strings.HasPrefix(a, "10.0.1.") }) {
			t.Errorf("resumed run used the edited settings: %+v", c)
		}
	}

	before = len(e.run.Calls())
	next, err := s.StartNow(ctx, admin, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "next run completed", func() bool { return status(t, e, next.ID) == inventory.RunCompleted })
	calls := e.run.Calls()[before:]
	if len(calls) == 0 {
		t.Fatal("next run made no nmap calls")
	}
	for _, c := range calls {
		if !slices.Equal(c.Opts.ProbePorts, []int{8080}) || !slices.Equal(c.Addrs, []string{"10.0.1.1", "10.0.1.2"}) {
			t.Errorf("next run did not use the edited settings: %+v", c)
		}
	}
}
