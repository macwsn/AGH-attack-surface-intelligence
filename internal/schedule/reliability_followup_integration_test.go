//go:build integration

package schedule_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/scantest"
	"asi/internal/schedule"
)

func TestStalledRunOfDefinitionIsPausedAndResumedInNextWindow(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := e.st.CreateDefinition(ctx, admin, definition("stalled"))
	if err != nil {
		t.Fatal(err)
	}
	s := e.scheduler(t, ctx)
	e.clock.Set("2026-11-17T11:00:00Z")
	step(t, s)

	run, err := e.st.StartRun(ctx, d.ID, time.Date(2026, 11, 16, 21, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Pool.Exec(ctx, `UPDATE runs SET heartbeat_at = '2026-11-16T21:00:00Z' WHERE id = $1`, run.ID); err != nil {
		t.Fatal(err)
	}

	e.clock.Set("2026-11-17T12:00:00Z")
	step(t, s)
	if st := status(t, e, run.ID); st != inventory.RunPaused {
		t.Fatalf("run with a heartbeat 15 hours old and no live executor: status after a scheduler step = %s, want paused", st)
	}
	if len(e.run.Calls()) != 0 {
		t.Fatal("the stalled run resumed outside its window")
	}

	e.clock.Set("2026-11-17T21:00:00Z")
	step(t, s)
	waitFor(t, "stalled run completed in the next window", func() bool { return status(t, e, run.ID) == inventory.RunCompleted })
	if n := len(runsOf(t, e, d.ID)); n != 1 {
		t.Errorf("runs = %d, want the stalled run resumed, not a new one", n)
	}
}

func TestScheduledStartRefusesAddressesTimesPortsAboveCeiling(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wide := definition("wide")
	wide.Settings.Targets, wide.Settings.Excludes = []string{"10.0.0.0/14"}, nil
	d, err := e.st.CreateDefinition(ctx, admin, wide)
	if err != nil {
		t.Fatal(err)
	}
	ports := make([]string, 1001)
	for i := range ports {
		ports[i] = fmt.Sprint(i + 1)
	}
	if _, err := e.db.Pool.Exec(ctx, `UPDATE scan_definitions SET settings = settings || jsonb_build_object('ports', `+"'["+strings.Join(ports, ",")+"]'::jsonb"+`) WHERE id = $1`, d.ID); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var logs []string
	s := &schedule.Scheduler{
		Store:   e.st,
		Scanner: &scan.Scanner{Store: e.inv, Runner: e.run, Clock: scantest.NewClock(time.Unix(0, 0))},
		Now:     e.clock.Now,
		Logf: func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			logs = append(logs, fmt.Sprintf(format, args...))
		},
	}
	s.Start(ctx)
	t.Cleanup(s.Wait)
	defer cancel()
	e.nmap.set(true, 0)

	e.clock.Set("2026-11-17T21:00:00Z")
	stepErr := s.Step()
	if runs := runsOf(t, e, d.ID); len(runs) != 0 {
		t.Fatalf("scheduled start of 262144 addresses x 1001 ports: %d runs started, want the start refused above the work ceiling", len(runs))
	}
	mu.Lock()
	text := strings.Join(logs, "\n")
	mu.Unlock()
	if stepErr != nil {
		text += "\n" + stepErr.Error()
	}
	if !strings.Contains(text, "26214") || !strings.Contains(text, "1001") {
		t.Fatalf("scheduled start refused with %q, want a message naming 262144 addresses and 1001 ports", text)
	}
}
