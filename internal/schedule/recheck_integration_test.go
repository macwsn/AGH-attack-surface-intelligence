//go:build integration

package schedule_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
	"asi/internal/schedule"
)

type sshLAN struct {
	mu sync.Mutex
	up map[string]bool
}

func (l *sshLAN) set(addrs ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.up = map[string]bool{}
	for _, a := range addrs {
		l.up[a] = true
	}
}

func (l *sshLAN) hosts(addrs []string, ports []int) []nmap.Host {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []nmap.Host
	for _, a := range addrs {
		if !l.up[a] {
			continue
		}
		h := nmap.Host{Address: a, Up: true}
		if slices.Contains(ports, 22) {
			h.Ports = []nmap.Port{{Number: 22, Protocol: "tcp", State: "open", Service: "ssh"}}
		}
		out = append(out, h)
	}
	return out
}

func (l *sshLAN) runner() *nmaptest.Runner {
	return &nmaptest.Runner{
		DiscoverFunc: func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			return l.hosts(addrs, nil), nil
		},
		ServicesFunc: func(_ context.Context, addrs []string, ports []int, _ nmap.Options) ([]nmap.Host, error) {
			return l.hosts(addrs, ports), nil
		},
	}
}

func (e *env) rhythmScheduler(t *testing.T, ctx context.Context, r *nmaptest.Runner) *schedule.Scheduler {
	t.Helper()
	tr := &scantest.Transport{Handler: http.NotFoundHandler()}
	s := &schedule.Scheduler{
		Store:   e.st,
		Scanner: &scan.Scanner{Store: e.inv, Runner: r, Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))},
		Now:     e.clock.Now,
		Logf:    t.Logf,
	}
	s.Start(ctx)
	t.Cleanup(s.Wait)
	return s
}

func rhythmDefinition(name string) schedule.Definition {
	return schedule.Definition{
		Name:          name,
		Enabled:       true,
		InactiveAfter: 10,
		Settings: inventory.RunSettings{
			Targets:   []string{"10.0.0.0/28"},
			Ports:     []int{22},
			MaxRate:   1000,
			Workers:   1,
			GroupSize: 16,
		},
		Schedule: schedule.Schedule{
			Timezone:     "UTC",
			Frequency:    schedule.Frequency{Kind: schedule.FrequencyInterval, Every: "24h"},
			RecheckEvery: "1h",
		},
	}
}

func (e *env) stampGroups(t *testing.T, runID int64, at time.Time) {
	t.Helper()
	if _, err := e.db.Pool.Exec(context.Background(), `UPDATE run_groups SET completed_at = $2 WHERE run_id = $1`, runID, at); err != nil {
		t.Fatal(err)
	}
}

func discovered(calls []nmaptest.Call) []string {
	var out []string
	for _, c := range calls {
		if c.Method == "Discover" {
			for _, a := range c.Addrs {
				if !slices.Contains(out, a) {
					out = append(out, a)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

func latestRun(t *testing.T, e *env, defID int64) schedule.Run {
	t.Helper()
	runs := runsOf(t, e, defID)
	if len(runs) == 0 {
		t.Fatal("no runs")
	}
	return runs[0]
}

// REQ-SCHEDULE-009
func TestSchedulerFullAndHourlyRechecks(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := e.st.CreateDefinition(ctx, admin, rhythmDefinition("rhythm"))
	if err != nil {
		t.Fatal(err)
	}
	lan := &sshLAN{}
	lan.set("10.0.0.5", "10.0.0.9")
	r := lan.runner()
	s := e.rhythmScheduler(t, ctx, r)

	t0 := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	tick := func(at time.Time) int {
		t.Helper()
		e.clock.Set(at.Format(time.RFC3339))
		before := len(runsOf(t, e, d.ID))
		step(t, s)
		runs := runsOf(t, e, d.ID)
		if len(runs) > before {
			waitFor(t, "run completed", func() bool { return status(t, e, runs[0].ID) == inventory.RunCompleted })
			e.stampGroups(t, runs[0].ID, at)
		}
		return len(runs) - before
	}

	if n := tick(t0); n != 1 {
		t.Fatalf("first step started %d runs, want 1", n)
	}
	full := latestRun(t, e, d.ID)
	if full.Settings.RunMode() != inventory.ModeFull || len(full.Settings.Hosts) != 0 {
		t.Fatalf("first run settings = %+v, want a full run", full.Settings)
	}
	if got := discovered(r.Calls()); len(got) != 14 {
		t.Fatalf("full run discovered %d addresses, want 14", len(got))
	}
	if n := tick(t0.Add(30 * time.Minute)); n != 0 {
		t.Fatalf("a run started 30 minutes after the full run")
	}
	for h := 1; h <= 5; h++ {
		before := len(r.Calls())
		if n := tick(t0.Add(time.Duration(h) * time.Hour)); n != 1 {
			t.Fatalf("hour %d: %d runs started, want one recheck", h, n)
		}
		run := latestRun(t, e, d.ID)
		if run.Settings.RunMode() != inventory.ModeRecheck || !slices.Equal(run.Settings.Hosts, []string{"10.0.0.5", "10.0.0.9"}) {
			t.Fatalf("hour %d: run settings = %+v, want a recheck of 10.0.0.5 and 10.0.0.9", h, run.Settings)
		}
		if got := discovered(r.Calls()[before:]); !slices.Equal(got, []string{"10.0.0.5", "10.0.0.9"}) {
			t.Errorf("hour %d: recheck discovered %v", h, got)
		}
		if n := tick(t0.Add(time.Duration(h)*time.Hour + 30*time.Minute)); n != 0 {
			t.Fatalf("hour %d: a run started 30 minutes after a recheck", h)
		}
	}
	if n := tick(t0.Add(24 * time.Hour)); n != 1 {
		t.Fatal("no run 24h after the full run")
	}
	if run := latestRun(t, e, d.ID); run.Settings.RunMode() != inventory.ModeFull {
		t.Errorf("run 24h after the full run is %s, want full", run.Settings.RunMode())
	}
	modes := []string{}
	for _, run := range runsOf(t, e, d.ID) {
		modes = append(modes, run.Settings.RunMode())
	}
	want := []string{"full", "recheck", "recheck", "recheck", "recheck", "recheck", "full"}
	slices.Reverse(modes)
	if !slices.Equal(modes, want) {
		t.Errorf("run modes = %v, want %v", modes, want)
	}
}

// REQ-SCHEDULE-009
func TestSchedulerWithoutRecheckEveryUnchanged(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	def := rhythmDefinition("plain")
	def.Schedule.RecheckEvery = ""
	d, err := e.st.CreateDefinition(ctx, admin, def)
	if err != nil {
		t.Fatal(err)
	}
	lan := &sshLAN{}
	lan.set("10.0.0.5")
	s := e.rhythmScheduler(t, ctx, lan.runner())
	t0 := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	for h := 0; h <= 24; h++ {
		e.clock.Set(t0.Add(time.Duration(h) * time.Hour).Format(time.RFC3339))
		step(t, s)
		runs := runsOf(t, e, d.ID)
		waitFor(t, "run completed", func() bool { return status(t, e, runs[0].ID) == inventory.RunCompleted })
	}
	runs := runsOf(t, e, d.ID)
	if len(runs) != 2 {
		t.Fatalf("runs = %d, want 2 full runs 24h apart", len(runs))
	}
	for _, run := range runs {
		if run.Settings.RunMode() != inventory.ModeFull {
			t.Errorf("run %s mode %s, want full", run.Name, run.Settings.RunMode())
		}
	}
}

// REQ-SCHEDULE-009
func TestDueRecheckWithoutCompletedRunStartsFull(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := e.st.CreateDefinition(ctx, admin, rhythmDefinition("failed-first"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := e.st.StartRun(ctx, d.ID, time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.inv.SetRunStatus(ctx, first.ID, inventory.RunFailed); err != nil {
		t.Fatal(err)
	}
	lan := &sshLAN{}
	lan.set("10.0.0.5")
	s := e.rhythmScheduler(t, ctx, lan.runner())
	if _, err := s.StartNow(ctx, admin, d.ID, inventory.ModeRecheck); err == nil || !strings.Contains(err.Error(), "no earlier run to recheck") ||
		!errors.Is(err, inventory.ErrNoRecheckBase) {
		t.Fatalf("StartNow recheck without a completed run: err = %v", err)
	}
	if n := len(runsOf(t, e, d.ID)); n != 1 {
		t.Fatalf("StartNow recheck without a base created a run: %d runs", n)
	}
	e.clock.Set("2026-11-16T11:00:00Z")
	step(t, s)
	runs := runsOf(t, e, d.ID)
	if len(runs) != 2 || runs[0].Settings.RunMode() != inventory.ModeFull {
		t.Fatalf("due recheck without a completed run: runs = %d, latest mode %s, want a full run", len(runs), runs[0].Settings.RunMode())
	}
	waitFor(t, "full run completed", func() bool { return status(t, e, runs[0].ID) == inventory.RunCompleted })

	run, err := s.StartNow(ctx, admin, d.ID, inventory.ModeRecheck)
	if err != nil {
		t.Fatalf("StartNow recheck: %v", err)
	}
	if run.Settings.RunMode() != inventory.ModeRecheck || len(run.Settings.Hosts) != 0 {
		t.Errorf("manual recheck settings = %+v", run.Settings)
	}
	waitFor(t, "manual recheck completed", func() bool { return status(t, e, run.ID) == inventory.RunCompleted })
	if _, err := s.StartNow(ctx, admin, d.ID, "fast"); err == nil || !strings.Contains(err.Error(), "invalid mode") {
		t.Errorf("StartNow with mode fast: err = %v", err)
	}
	got, err := e.st.Run(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Packets == 0 {
		t.Error("recheck run lists 0 packets")
	}
}

func recordHistory(t *testing.T, e *env, defID int64, at time.Time, seen ...string) {
	t.Helper()
	ctx := context.Background()
	run, err := e.st.StartRun(ctx, defID, at)
	if err != nil {
		t.Fatal(err)
	}
	g := inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.3", "10.0.0.5", "10.0.0.9"}, Duration: time.Second}
	for _, a := range seen {
		g.Hosts = append(g.Hosts, inventory.HostResult{Address: a,
			Services: []inventory.ServiceResult{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}})
	}
	if err := e.inv.RecordGroup(ctx, run.ID, g); err != nil {
		t.Fatal(err)
	}
	if err := e.inv.SetRunStatus(ctx, run.ID, inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
	e.stampGroups(t, run.ID, at)
}

// REQ-SCHEDULE-009
func TestScheduledRecheckPicksHostsByAvailability(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	def := rhythmDefinition("picking")
	def.Schedule.Frequency = schedule.Frequency{Kind: schedule.FrequencyInterval, Every: "168h"}
	d, err := e.st.CreateDefinition(ctx, admin, def)
	if err != nil {
		t.Fatal(err)
	}
	const a, b, c = "10.0.0.5", "10.0.0.9", "10.0.0.3"
	day := func(n, hour int) time.Time { return time.Date(2026, 11, 1+n, hour, 0, 0, 0, time.UTC) }
	recordHistory(t, e, d.ID, day(1, 5), a, b, c)
	for n := 1; n <= 3; n++ {
		recordHistory(t, e, d.ID, day(n, 10), a, b)
	}
	for n := 4; n <= 6; n++ {
		recordHistory(t, e, d.ID, day(n, 2), a, c)
	}
	recordHistory(t, e, d.ID, day(6, 10), a, b)

	exp, err := e.inv.Export(ctx, latestRun(t, e, d.ID).Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range exp.Hosts {
		p := h.Availability.Profile()
		switch h.Address {
		case a:
			if p.Periodic() {
				t.Errorf("fixture: %s is periodic: %+v", a, p)
			}
		case b:
			if p.Expected(2) != inventory.ExpectedDown {
				t.Errorf("fixture: %s expected at 02 = %q, want down (%+v)", b, p.Expected(2), p)
			}
		case c:
			if p.Expected(2) != inventory.ExpectedUp {
				t.Errorf("fixture: %s expected at 02 = %q, want up (%+v)", c, p.Expected(2), p)
			}
		}
	}

	lan := &sshLAN{}
	lan.set(a, c)
	r := lan.runner()
	s := e.rhythmScheduler(t, ctx, r)

	now := day(7, 2).Add(30 * time.Minute)
	e.clock.Set(now.Format(time.RFC3339))
	step(t, s)
	run := latestRun(t, e, d.ID)
	if run.Settings.RunMode() != inventory.ModeRecheck || !slices.Equal(run.Settings.Hosts, []string{c, a}) {
		t.Fatalf("recheck at 02:30 settings = %+v, want hosts [%s %s] (expected up first, expected-down %s seen 16h ago skipped)", run.Settings, c, a, b)
	}
	waitFor(t, "recheck completed", func() bool { return status(t, e, run.ID) == inventory.RunCompleted })
	e.stampGroups(t, run.ID, now)
	var order []string
	for _, call := range r.Calls() {
		for _, addr := range call.Addrs {
			if !slices.Contains(order, addr) {
				order = append(order, addr)
			}
		}
	}
	if !slices.Equal(order, []string{c, a}) {
		t.Errorf("recheck contacted %v, want [%s %s] in that order", order, c, a)
	}

	e.clock.Set(now.Add(20 * time.Minute).Format(time.RFC3339))
	step(t, s)
	if latestRun(t, e, d.ID).ID != run.ID {
		t.Fatal("a recheck started 20 minutes after the last one")
	}

	next := day(8, 2).Add(30 * time.Minute)
	e.clock.Set(next.Format(time.RFC3339))
	step(t, s)
	run2 := latestRun(t, e, d.ID)
	if run2.ID == run.ID || run2.Settings.RunMode() != inventory.ModeRecheck || !slices.Equal(run2.Settings.Hosts, []string{c, a, b}) {
		t.Fatalf("recheck a day later settings = %+v, want hosts [%s %s %s] (%s unseen for 24h included)", run2.Settings, c, a, b, b)
	}
	waitFor(t, "second recheck completed", func() bool { return status(t, e, run2.ID) == inventory.RunCompleted })
}

// REQ-SCHEDULE-009
func TestScheduledRecheckNotStartedWhenNothingPicked(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	def := rhythmDefinition("nothing")
	def.Schedule.Frequency = schedule.Frequency{Kind: schedule.FrequencyInterval, Every: "168h"}
	def.Schedule.RecheckEvery = "2h"
	d, err := e.st.CreateDefinition(ctx, admin, def)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	recordHistory(t, e, d.ID, at, "10.0.0.5")
	e.stampGroups(t, latestRun(t, e, d.ID).ID, at.Add(90*time.Minute))
	lan := &sshLAN{}
	r := lan.runner()
	s := e.rhythmScheduler(t, ctx, r)
	e.clock.Set(at.Add(2 * time.Hour).Format(time.RFC3339))
	step(t, s)
	if n := len(runsOf(t, e, d.ID)); n != 1 || len(r.Calls()) != 0 {
		t.Fatalf("runs = %d, nmap calls = %d: a recheck started with no host due", n, len(r.Calls()))
	}
	e.clock.Set(at.Add(210 * time.Minute).Format(time.RFC3339))
	step(t, s)
	if n := len(runsOf(t, e, d.ID)); n != 2 {
		t.Fatalf("runs = %d, want the recheck once the host is due", n)
	}
	waitFor(t, "recheck completed", func() bool { return status(t, e, latestRun(t, e, d.ID).ID) == inventory.RunCompleted })
}

// REQ-SCHEDULE-009
func TestSchedulerRechecksAllHostsWhenGroupsFinishAfterRunStart(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	def := rhythmDefinition("staggered")
	def.Settings.GroupSize = 4
	d, err := e.st.CreateDefinition(ctx, admin, def)
	if err != nil {
		t.Fatal(err)
	}
	lan := &sshLAN{}
	lan.set("10.0.0.1", "10.0.0.14")
	s := e.rhythmScheduler(t, ctx, lan.runner())

	t0 := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	var starts []time.Time
	for at := t0; at.Before(t0.Add(5*time.Hour + 30*time.Minute)); at = at.Add(time.Minute) {
		e.clock.Set(at.Format(time.RFC3339))
		before := len(runsOf(t, e, d.ID))
		step(t, s)
		runs := runsOf(t, e, d.ID)
		if len(runs) == before {
			continue
		}
		waitFor(t, "run completed", func() bool { return status(t, e, runs[0].ID) == inventory.RunCompleted })
		if _, err := e.db.Pool.Exec(ctx, `UPDATE run_groups SET completed_at = $2::timestamptz + (group_index + 1) * interval '1 minute' WHERE run_id = $1`, runs[0].ID, at); err != nil {
			t.Fatal(err)
		}
		if len(starts) > 0 && !slices.Equal(runs[0].Settings.Hosts, []string{"10.0.0.1", "10.0.0.14"}) {
			t.Errorf("run at %s: hosts %v, want a recheck of 10.0.0.1 and 10.0.0.14", at.Format("15:04"), runs[0].Settings.Hosts)
		}
		starts = append(starts, at)
	}
	if len(starts) != 6 {
		t.Fatalf("runs started at %v, want a full run and 5 rechecks", starts)
	}
	for i := 1; i < len(starts); i++ {
		if gap := starts[i].Sub(starts[i-1]); gap < time.Hour || gap > time.Hour+5*time.Minute {
			t.Errorf("run %d started %s after the previous one, want about an hour", i, gap)
		}
	}
}
