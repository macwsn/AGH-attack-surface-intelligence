//go:build integration

package schedule_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/schedule"
)

// REQ-SCHEDULE-009
func TestRechecksOfTwoDefinitionsWithDisjointTargetsRunOnScheduleOnOwnHosts(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const hostA, hostB = "10.0.0.5", "10.0.1.5"
	lan := &sshLAN{}
	lan.set(hostA, hostB)
	s := e.rhythmScheduler(t, ctx, lan.runner())

	defA, err := e.st.CreateDefinition(ctx, admin, rhythmDefinition("scope-a"))
	if err != nil {
		t.Fatal(err)
	}
	var defB schedule.Definition
	t0 := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	seen := map[int64]int{}
	rechecks := map[int64][]string{}
	for at := t0; !at.After(t0.Add(5 * time.Hour)); at = at.Add(30 * time.Minute) {
		if at.Equal(t0.Add(30 * time.Minute)) {
			b := rhythmDefinition("scope-b")
			b.Settings.Targets = []string{"10.0.1.0/28"}
			if defB, err = e.st.CreateDefinition(ctx, admin, b); err != nil {
				t.Fatal(err)
			}
		}
		e.clock.Set(at.Format(time.RFC3339))
		if err := s.Step(); err != nil {
			t.Errorf("step at %s: %v", at.Format("15:04"), err)
		}
		for _, d := range []schedule.Definition{defA, defB} {
			if d.ID == 0 {
				continue
			}
			runs := runsOf(t, e, d.ID)
			for i := len(runs) - 1 - seen[d.ID]; i >= 0; i-- {
				run := runs[i]
				waitFor(t, "run finished", func() bool {
					st := status(t, e, run.ID)
					return st == inventory.RunCompleted || st == inventory.RunFailed
				})
				e.stampGroups(t, run.ID, at)
				if st := status(t, e, run.ID); st != inventory.RunCompleted {
					t.Errorf("%s at %s: %s run %s is %s, want completed", d.Name, at.Format("15:04"), run.Settings.RunMode(), run.Name, st)
				}
				if run.Settings.RunMode() == inventory.ModeRecheck {
					rechecks[d.ID] = append(rechecks[d.ID], at.Format("15:04"))
					own := hostA
					if d.ID == defB.ID {
						own = hostB
					}
					if !slices.Equal(run.Settings.Hosts, []string{own}) {
						t.Errorf("%s recheck at %s: hosts %v, want only its own host %s", d.Name, at.Format("15:04"), run.Settings.Hosts, own)
					}
				}
			}
			seen[d.ID] = len(runs)
		}
	}
	if want := []string{"11:00", "12:00", "13:00", "14:00", "15:00"}; !slices.Equal(rechecks[defA.ID], want) {
		t.Errorf("scope-a rechecks at %v, want %v", rechecks[defA.ID], want)
	}
	if want := []string{"11:30", "12:30", "13:30", "14:30"}; !slices.Equal(rechecks[defB.ID], want) {
		t.Errorf("scope-b rechecks at %v, want %v", rechecks[defB.ID], want)
	}
}
