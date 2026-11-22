package schedule

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/scan"
)

const DefaultTick = 30 * time.Second

type Scheduler struct {
	Store   *Store
	Scanner *scan.Scanner
	Now     func() time.Time
	Tick    time.Duration
	Logf    func(format string, args ...any)

	mu    sync.Mutex
	base  context.Context
	execs map[int64]*execution
	wg    sync.WaitGroup

	recovered bool
}

type execution struct {
	runID    int64
	deadline time.Time
	cancel   context.CancelFunc
	done     chan struct{}
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Scheduler) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.base = ctx
	s.execs = map[int64]*execution{}
}

func (s *Scheduler) recover() error {
	if s.recovered {
		return nil
	}
	n, err := s.Store.PauseOrphans(s.base)
	if err != nil {
		return err
	}
	s.recovered = true
	if n > 0 {
		s.logf("scheduler: %d interrupted runs marked paused, they resume in their next window", n)
	}
	return nil
}

func (s *Scheduler) Loop() {
	tick := s.Tick
	if tick <= 0 {
		tick = DefaultTick
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		if err := s.Step(); err != nil {
			s.logf("scheduler: %v", err)
		}
		select {
		case <-s.base.Done():
			s.Wait()
			return
		case <-t.C:
		}
	}
}

func (s *Scheduler) Wait() { s.wg.Wait() }

func (s *Scheduler) Step() error {
	if err := s.base.Err(); err != nil {
		return nil
	}
	if err := s.recover(); err != nil {
		return err
	}
	now := s.now()
	defs, err := s.Store.Definitions(s.base)
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range defs {
		if err := s.stepDefinition(d, now); err != nil {
			errs = append(errs, fmt.Errorf("scan %q: %w", d.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Scheduler) stepDefinition(d Definition, now time.Time) error {
	s.mu.Lock()
	ex := s.execs[d.ID]
	s.mu.Unlock()
	if ex != nil {
		if !ex.deadline.IsZero() && !now.Before(ex.deadline) {
			ex.cancel()
		}
		return nil
	}
	if !d.Enabled {
		return nil
	}
	open, ok, err := s.Store.OpenRun(s.base, d.ID)
	if err != nil {
		return err
	}
	if ok {
		if open.Stalled {
			paused, err := s.Store.PauseStalled(s.base, open.ID)
			if err != nil || !paused {
				return err
			}
			s.logf("scheduler: run %q stalled (no heartbeat and no live executor), marked paused, it resumes in its next window", open.Name)
			open.Status = inventory.RunPaused
		}
		if open.Held {
			return nil
		}
		if w, in := open.Schedule.WindowAt(now); in {
			return s.launch(d.ID, open, w.End)
		}
		return nil
	}
	w, in := d.Schedule.WindowAt(now)
	if !in {
		return nil
	}
	mode, hosts, err := s.nextRun(d, now, w)
	if err != nil || mode == "" {
		return err
	}
	if err := scan.CheckWork(d.Settings); err != nil {
		return fmt.Errorf("scheduled start refused: %w", err)
	}
	run, err := s.Store.StartRunMode(s.base, d.ID, now, mode, hosts)
	if errors.Is(err, ErrRunOpen) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.launch(d.ID, run, w.End)
}

func (s *Scheduler) nextRun(d Definition, now time.Time, w Span) (string, []string, error) {
	every, rechecks := d.Schedule.RecheckInterval()
	if !rechecks {
		if d.Schedule.Due(d.LastRunAt, now, w) {
			return inventory.ModeFull, nil, nil
		}
		return "", nil, nil
	}
	lastFull, err := s.Store.LastFullRunAt(s.base, d.ID)
	if err != nil {
		return "", nil, err
	}
	if d.Schedule.Due(lastFull, now, w) {
		return inventory.ModeFull, nil, nil
	}
	if d.LastRunAt != nil && now.Before(d.LastRunAt.Add(every)) {
		return "", nil, nil
	}
	base, ok, err := s.Store.LatestCompletedRun(s.base, d.ID)
	if err != nil {
		return "", nil, err
	}
	if !ok {
		return inventory.ModeFull, nil, nil
	}
	candidates, err := s.recheckCandidates(s.base, d, base)
	if err != nil {
		return "", nil, err
	}
	var baseCovered time.Time
	for _, c := range candidates {
		if !c.LastCovered.Before(base.StartedAt) && c.LastCovered.After(baseCovered) {
			baseCovered = c.LastCovered
		}
	}
	for i, c := range candidates {
		if !c.LastCovered.Before(base.StartedAt) {
			candidates[i].LastCovered = baseCovered
		}
	}
	loc, err := d.Schedule.Location()
	if err != nil {
		return "", nil, err
	}
	picked := PickRecheck(now.In(loc), every, candidates)
	if len(picked) == 0 {
		return "", nil, nil
	}
	return inventory.ModeRecheck, picked, nil
}

func (s *Scheduler) recheckCandidates(ctx context.Context, d Definition, base Run) ([]RecheckHost, error) {
	exp, err := s.Scanner.Store.Export(ctx, base.Name)
	if err != nil {
		return nil, fmt.Errorf("recheck hosts: %w", err)
	}
	set, err := s.Scanner.TargetSet(ctx, d.Settings)
	if err != nil {
		return nil, fmt.Errorf("recheck hosts: %w", err)
	}
	own := exp.Hosts[:0:0]
	for _, h := range exp.Hosts {
		if a, err := netip.ParseAddr(h.Address); err == nil && set.Contains(a) {
			own = append(own, h)
		}
	}
	return recheckHosts(own, d.Settings.Ports), nil
}

func (s *Scheduler) launch(defID int64, run Run, deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.execs[defID]; old != nil && old.runID == run.ID {
		return ErrRunOpen
	}
	ctx, cancel := context.WithCancel(s.base)
	ex := &execution{runID: run.ID, deadline: deadline, cancel: cancel, done: make(chan struct{})}
	s.execs[defID] = ex
	s.wg.Go(func() {
		defer close(ex.done)
		err := s.Scanner.Run(ctx, run.Run)
		cancel()
		s.mu.Lock()
		if s.execs[defID] == ex {
			delete(s.execs, defID)
		}
		s.mu.Unlock()
		if err != nil {
			s.logf("scheduler: %v", err)
		}
	})
	return nil
}

func (s *Scheduler) StartNow(ctx context.Context, actor auth.Actor, defID int64, mode ...string) (Run, error) {
	m := inventory.ModeFull
	if len(mode) > 0 && mode[0] != "" {
		m = mode[0]
	}
	if !inventory.ValidMode(m) {
		return Run{}, fmt.Errorf("start scan %d: invalid mode %q, want %s or %s", defID, m, inventory.ModeFull, inventory.ModeRecheck)
	}
	if m == inventory.ModeRecheck {
		if err := s.checkRecheckBase(ctx, defID); err != nil {
			return Run{}, err
		}
	}
	d, err := s.Store.Definition(ctx, defID)
	if err != nil {
		return Run{}, err
	}
	if err := scan.CheckWork(d.Settings); err != nil {
		return Run{}, fmt.Errorf("start scan %q: %w", d.Name, err)
	}
	run, err := s.Store.StartRunMode(ctx, defID, s.now(), m, nil)
	if err != nil {
		return Run{}, err
	}
	if err := s.Store.Audit(ctx, actor, auditStart, run.Name); err != nil {
		return Run{}, err
	}
	return run, s.launch(defID, run, time.Time{})
}

func (s *Scheduler) checkRecheckBase(ctx context.Context, defID int64) error {
	d, err := s.Store.Definition(ctx, defID)
	if err != nil {
		return err
	}
	base, ok, err := s.Store.LatestCompletedRun(ctx, defID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("start recheck of scan %q: %w: no completed run of the scan definition", d.Name, inventory.ErrNoRecheckBase)
	}
	candidates, err := s.recheckCandidates(ctx, d, base)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		return fmt.Errorf("start recheck of scan %q: %w: run %q has no known open service", d.Name, inventory.ErrNoRecheckBase, base.Name)
	}
	return nil
}

func (s *Scheduler) Pause(ctx context.Context, actor auth.Actor, runID int64) error {
	run, err := s.Store.Run(ctx, runID)
	if err != nil {
		return err
	}
	if !run.Open() {
		return ErrNotOpen
	}
	if err := s.Store.setHeld(ctx, actor, run, true); err != nil {
		return err
	}
	s.mu.Lock()
	ex := s.execs[run.DefinitionID]
	s.mu.Unlock()
	if ex == nil || ex.runID != runID {
		return nil
	}
	ex.cancel()
	select {
	case <-ex.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Scheduler) Resume(ctx context.Context, actor auth.Actor, runID int64) error {
	run, err := s.Store.Run(ctx, runID)
	if err != nil {
		return err
	}
	if run.Status != inventory.RunPaused || run.DefinitionID == 0 {
		return ErrNotPaused
	}
	if err := s.Store.setHeld(ctx, actor, run, false); err != nil {
		return err
	}
	run.Held = false
	return s.launch(run.DefinitionID, run, time.Time{})
}
