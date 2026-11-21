package schedule

import (
	"context"
	"errors"
	"fmt"
	"log"
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
		if open.Held {
			return nil
		}
		if w, in := open.Schedule.WindowAt(now); in {
			return s.launch(d.ID, open, w.End)
		}
		return nil
	}
	w, in := d.Schedule.WindowAt(now)
	if !in || !d.Schedule.Due(d.LastRunAt, now, w) {
		return nil
	}
	run, err := s.Store.StartRun(s.base, d.ID, now)
	if errors.Is(err, ErrRunOpen) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.launch(d.ID, run, w.End)
}

func (s *Scheduler) launch(defID int64, run Run, deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.execs[defID] != nil {
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
		delete(s.execs, defID)
		s.mu.Unlock()
		if err != nil {
			s.logf("scheduler: %v", err)
		}
	})
	return nil
}

func (s *Scheduler) StartNow(ctx context.Context, actor auth.Actor, defID int64) (Run, error) {
	s.mu.Lock()
	busy := s.execs[defID] != nil
	s.mu.Unlock()
	if busy {
		return Run{}, ErrRunOpen
	}
	run, err := s.Store.StartRun(ctx, defID, s.now())
	if err != nil {
		return Run{}, err
	}
	if err := s.Store.Audit(ctx, actor, auditStart, run.Name); err != nil {
		return Run{}, err
	}
	return run, s.launch(defID, run, time.Time{})
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
	s.mu.Lock()
	busy := s.execs[run.DefinitionID] != nil
	s.mu.Unlock()
	if busy {
		return ErrRunOpen
	}
	if err := s.Store.setHeld(ctx, actor, run, false); err != nil {
		return err
	}
	run.Held = false
	return s.launch(run.DefinitionID, run, time.Time{})
}
