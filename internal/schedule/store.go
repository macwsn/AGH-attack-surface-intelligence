package schedule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/store"
	"asi/internal/targets"
)

var (
	ErrUnknownDefinition = errors.New("unknown scan definition")
	ErrDefinitionExists  = errors.New("a scan definition with this name already exists")
	ErrRunOpen           = errors.New("this scan already has a run in progress or paused")
	ErrUnknownRun        = errors.New("unknown run")
	ErrNotPaused         = errors.New("the run is not paused")
	ErrNotOpen           = errors.New("the run is not in progress or paused")
)

const (
	auditCreate  = "scan.create"
	auditUpdate  = "scan.update"
	auditEnable  = "scan.enable"
	auditDisable = "scan.disable"
	auditDelete  = "scan.delete"
	auditStart   = "scan.start"
	auditPause   = "scan.pause"
	auditResume  = "scan.resume"
)

type Definition struct {
	ID            int64
	Name          string
	Enabled       bool
	InactiveAfter int
	Settings      inventory.RunSettings
	Schedule      Schedule
	LastRunAt     *time.Time
	UpdatedAt     time.Time
}

type Run struct {
	inventory.Run
	DefinitionID      int64
	DefinitionDeleted bool
	Held              bool
	Schedule          Schedule
	AddressTotal      int
}

func (r Run) Open() bool {
	return r.Status == inventory.RunRunning || r.Status == inventory.RunPaused
}

func (d Definition) Validate() error {
	var errs []error
	if strings.TrimSpace(d.Name) == "" {
		errs = append(errs, errors.New("name: enter a name"))
	}
	st := d.Settings
	if len(st.Targets) == 0 {
		errs = append(errs, errors.New("targets: enter at least one target"))
	} else if _, err := targets.ParseHosts(strings.NewReader(strings.Join(st.Targets, "\n"))); err != nil {
		errs = append(errs, fmt.Errorf("targets: %w", err))
	} else if err := scan.CheckWork(st); err != nil {
		errs = append(errs, fmt.Errorf("targets: %w", err))
	}
	if _, err := targets.ParseHosts(strings.NewReader(strings.Join(st.Excludes, "\n"))); err != nil {
		errs = append(errs, fmt.Errorf("excludes: %w", err))
	}
	if len(st.Ports) == 0 {
		errs = append(errs, errors.New("ports: enter at least one port"))
	}
	for _, p := range st.Ports {
		if p < 1 || p > 65535 {
			errs = append(errs, fmt.Errorf("ports: %d is not a port", p))
		}
	}
	if st.MaxRate < 2 {
		errs = append(errs, errors.New("max rate: enter at least 2 per second"))
	}
	if st.Workers < 1 {
		errs = append(errs, errors.New("workers: enter at least 1"))
	}
	if d.InactiveAfter < 1 {
		errs = append(errs, errors.New("inactive after: enter at least 1 run"))
	}
	if st.SignaturesDir != "" {
		if _, err := detect.LoadDir(st.SignaturesDir); err != nil {
			errs = append(errs, fmt.Errorf("signatures: %w", err))
		}
	}
	if _, err := d.Schedule.Location(); err != nil {
		errs = append(errs, fmt.Errorf("timezone: %w", err))
	}
	for i, w := range d.Schedule.Windows {
		if err := w.validate(); err != nil {
			errs = append(errs, fmt.Errorf("windows: window %d: %w", i+1, err))
		}
	}
	if err := d.Schedule.Frequency.validate(); err != nil {
		errs = append(errs, fmt.Errorf("frequency: %w", err))
	}
	if err := d.Schedule.validateRecheck(); err != nil {
		errs = append(errs, fmt.Errorf("recheck: %w", err))
	}
	return errors.Join(errs...)
}

func changedFields(a, b Definition) []string {
	var out []string
	add := func(name string, x, y any) {
		if !reflect.DeepEqual(x, y) {
			out = append(out, name)
		}
	}
	add("name", a.Name, b.Name)
	add("targets", a.Settings.Targets, b.Settings.Targets)
	add("excludes", a.Settings.Excludes, b.Settings.Excludes)
	add("ports", a.Settings.Ports, b.Settings.Ports)
	add("max rate", a.Settings.MaxRate, b.Settings.MaxRate)
	add("workers", a.Settings.Workers, b.Settings.Workers)
	add("group size", a.Settings.GroupSize, b.Settings.GroupSize)
	add("inactive after", a.InactiveAfter, b.InactiveAfter)
	add("signatures", a.Settings.SignaturesDir, b.Settings.SignaturesDir)
	add("volatile headers", a.Settings.VolatileHeaders, b.Settings.VolatileHeaders)
	add("timezone", a.Schedule.Timezone, b.Schedule.Timezone)
	add("windows", a.Schedule.Windows, b.Schedule.Windows)
	add("frequency", a.Schedule.Frequency, b.Schedule.Frequency)
	add("recheck every", a.Schedule.RecheckEvery, b.Schedule.RecheckEvery)
	return out
}

type Store struct {
	db  *store.Store
	inv *inventory.Inventory
}

func NewStore(db *store.Store, keys *store.Keyring) *Store {
	return &Store{db: db, inv: inventory.New(db, keys)}
}

const defColumns = `id, name, enabled, inactive_after, settings, scope, schedule, last_run_at, updated_at`

func (s *Store) scanDefinition(row pgx.Row) (Definition, error) {
	var (
		d                         Definition
		settings, scope, schedule []byte
	)
	if err := row.Scan(&d.ID, &d.Name, &d.Enabled, &d.InactiveAfter, &settings, &scope, &schedule, &d.LastRunAt, &d.UpdatedAt); err != nil {
		return Definition{}, err
	}
	if err := s.inv.OpenSettings(settings, scope, &d.Settings); err != nil {
		return Definition{}, fmt.Errorf("decode settings of scan %q: %w", d.Name, err)
	}
	if err := json.Unmarshal(schedule, &d.Schedule); err != nil {
		return Definition{}, fmt.Errorf("decode schedule of scan %q: %w", d.Name, err)
	}
	return d, nil
}

const runColumns = `id, name, inactive_after, started_at, finished_at, status, settings, scope,
	COALESCE(definition_id, 0), definition_deleted, held, COALESCE(schedule, '{}'), COALESCE(address_total, 0), packets, inflight_addresses, ` + stalled

const stalled = `(status = 'running' AND COALESCE(heartbeat_at, started_at) < now() - interval '60 seconds')`

func (s *Store) scanRun(row pgx.Row) (Run, error) {
	var (
		r                         Run
		settings, scope, schedule []byte
	)
	if err := row.Scan(&r.ID, &r.Name, &r.InactiveAfter, &r.StartedAt, &r.FinishedAt, &r.Status, &settings, &scope,
		&r.DefinitionID, &r.DefinitionDeleted, &r.Held, &schedule, &r.AddressTotal, &r.Packets, &r.InFlight, &r.Stalled); err != nil {
		return Run{}, err
	}
	if err := s.inv.OpenSettings(settings, scope, &r.Settings); err != nil {
		return Run{}, fmt.Errorf("decode settings of run %q: %w", r.Name, err)
	}
	if err := json.Unmarshal(schedule, &r.Schedule); err != nil {
		return Run{}, fmt.Errorf("decode schedule of run %q: %w", r.Name, err)
	}
	return r, nil
}

func writeAudit(ctx context.Context, tx pgx.Tx, actor auth.Actor, action, target string) error {
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log (actor, action, target, address) VALUES ($1, $2, $3, $4)`,
		actor.Username, action, target, actor.Addr); err != nil {
		return fmt.Errorf("write audit %s: %w", action, err)
	}
	return nil
}

func (s *Store) Audit(ctx context.Context, actor auth.Actor, action, target string) error {
	return s.db.Tx(ctx, func(tx pgx.Tx) error { return writeAudit(ctx, tx, actor, action, target) })
}

func (s *Store) Definitions(ctx context.Context) ([]Definition, error) {
	rows, err := s.db.Pool.Query(ctx, `SELECT `+defColumns+` FROM scan_definitions ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list scan definitions: %w", err)
	}
	defs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Definition, error) { return s.scanDefinition(row) })
	if err != nil {
		return nil, fmt.Errorf("list scan definitions: %w", err)
	}
	return defs, nil
}

func (s *Store) Definition(ctx context.Context, id int64) (Definition, error) {
	d, err := s.scanDefinition(s.db.Pool.QueryRow(ctx, `SELECT `+defColumns+` FROM scan_definitions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Definition{}, fmt.Errorf("%w: id %d", ErrUnknownDefinition, id)
	}
	if err != nil {
		return Definition{}, fmt.Errorf("read scan definition %d: %w", id, err)
	}
	return d, nil
}

func (s *Store) encode(d Definition) (settings string, scope []byte, schedule string, err error) {
	if d.Schedule.Windows == nil {
		d.Schedule.Windows = []Window{}
	}
	settings, scope, err = s.inv.SealSettings(d.Settings)
	if err != nil {
		return "", nil, "", err
	}
	b, err := json.Marshal(d.Schedule)
	if err != nil {
		return "", nil, "", fmt.Errorf("encode schedule: %w", err)
	}
	return settings, scope, string(b), nil
}

func uniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (s *Store) CreateDefinition(ctx context.Context, actor auth.Actor, d Definition) (Definition, error) {
	d.Name = strings.TrimSpace(d.Name)
	if err := d.Validate(); err != nil {
		return Definition{}, err
	}
	settings, scope, schedule, err := s.encode(d)
	if err != nil {
		return Definition{}, err
	}
	var out Definition
	err = s.db.Tx(ctx, func(tx pgx.Tx) error {
		out, err = s.scanDefinition(tx.QueryRow(ctx, `INSERT INTO scan_definitions (name, enabled, inactive_after, settings, scope, schedule)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+defColumns, d.Name, d.Enabled, d.InactiveAfter, settings, scope, schedule))
		if err != nil {
			return err
		}
		return writeAudit(ctx, tx, actor, auditCreate, d.Name)
	})
	if uniqueViolation(err) {
		return Definition{}, fmt.Errorf("%w: %q", ErrDefinitionExists, d.Name)
	}
	if err != nil {
		return Definition{}, fmt.Errorf("create scan definition %q: %w", d.Name, err)
	}
	return out, nil
}

func (s *Store) UpdateDefinition(ctx context.Context, actor auth.Actor, d Definition) (Definition, error) {
	d.Name = strings.TrimSpace(d.Name)
	if err := d.Validate(); err != nil {
		return Definition{}, err
	}
	settings, scope, schedule, err := s.encode(d)
	if err != nil {
		return Definition{}, err
	}
	var out Definition
	err = s.db.Tx(ctx, func(tx pgx.Tx) error {
		old, err := s.scanDefinition(tx.QueryRow(ctx, `SELECT `+defColumns+` FROM scan_definitions WHERE id = $1 FOR UPDATE`, d.ID))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: id %d", ErrUnknownDefinition, d.ID)
		}
		if err != nil {
			return err
		}
		changed := changedFields(old, d)
		if out, err = s.scanDefinition(tx.QueryRow(ctx, `UPDATE scan_definitions SET name = $2, inactive_after = $3,
				settings = $4, scope = $5, schedule = $6, updated_at = now() WHERE id = $1 RETURNING `+defColumns,
			d.ID, d.Name, d.InactiveAfter, settings, scope, schedule)); err != nil {
			return err
		}
		if len(changed) == 0 {
			return nil
		}
		return writeAudit(ctx, tx, actor, auditUpdate, old.Name+": "+strings.Join(changed, ", "))
	})
	if uniqueViolation(err) {
		return Definition{}, fmt.Errorf("%w: %q", ErrDefinitionExists, d.Name)
	}
	if err != nil {
		return Definition{}, fmt.Errorf("update scan definition %d: %w", d.ID, err)
	}
	return out, nil
}

func (s *Store) SetEnabled(ctx context.Context, actor auth.Actor, id int64, enabled bool) error {
	action := auditDisable
	if enabled {
		action = auditEnable
	}
	err := s.db.Tx(ctx, func(tx pgx.Tx) error {
		var name string
		err := tx.QueryRow(ctx, `UPDATE scan_definitions SET enabled = $2, updated_at = now() WHERE id = $1 RETURNING name`,
			id, enabled).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: id %d", ErrUnknownDefinition, id)
		}
		if err != nil {
			return err
		}
		return writeAudit(ctx, tx, actor, action, name)
	})
	if err != nil {
		return fmt.Errorf("%s scan definition %d: %w", action, id, err)
	}
	return nil
}

func (s *Store) DeleteDefinition(ctx context.Context, actor auth.Actor, id int64) error {
	err := s.db.Tx(ctx, func(tx pgx.Tx) error {
		var name string
		err := tx.QueryRow(ctx, `SELECT name FROM scan_definitions WHERE id = $1 FOR UPDATE`, id).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: id %d", ErrUnknownDefinition, id)
		}
		if err != nil {
			return err
		}
		var open bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM runs WHERE definition_id = $1 AND status IN ('running', 'paused'))`,
			id).Scan(&open); err != nil {
			return err
		}
		if open {
			return ErrRunOpen
		}
		if _, err := tx.Exec(ctx, `UPDATE runs SET definition_deleted = true WHERE definition_id = $1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scan_definitions WHERE id = $1`, id); err != nil {
			return err
		}
		return writeAudit(ctx, tx, actor, auditDelete, name)
	})
	if err != nil {
		return fmt.Errorf("delete scan definition %d: %w", id, err)
	}
	return nil
}

func (s *Store) StartRun(ctx context.Context, defID int64, at time.Time) (Run, error) {
	return s.StartRunMode(ctx, defID, at, inventory.ModeFull, nil)
}

func (s *Store) StartRunMode(ctx context.Context, defID int64, at time.Time, mode string, hosts []string) (Run, error) {
	if mode == "" {
		mode = inventory.ModeFull
	}
	if !inventory.ValidMode(mode) {
		return Run{}, fmt.Errorf("start run of scan %d: invalid mode %q, want %s or %s", defID, mode, inventory.ModeFull, inventory.ModeRecheck)
	}
	var run Run
	err := s.db.Tx(ctx, func(tx pgx.Tx) error {
		d, err := s.scanDefinition(tx.QueryRow(ctx, `SELECT `+defColumns+` FROM scan_definitions WHERE id = $1 FOR UPDATE`, defID))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: id %d", ErrUnknownDefinition, defID)
		}
		if err != nil {
			return err
		}
		var open bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM runs WHERE definition_id = $1 AND status IN ('running', 'paused'))`,
			defID).Scan(&open); err != nil {
			return err
		}
		if open {
			return ErrRunOpen
		}
		d.Settings.Mode, d.Settings.Hosts = mode, hosts
		settings, scope, schedule, err := s.encode(d)
		if err != nil {
			return err
		}
		base := d.Name + "-" + at.UTC().Format("20060102-150405")
		name := base
		for n := 2; ; n++ {
			var taken bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM runs WHERE name = $1)`, name).Scan(&taken); err != nil {
				return err
			}
			if !taken {
				break
			}
			name = fmt.Sprintf("%s-%d", base, n)
		}
		if run, err = s.scanRun(tx.QueryRow(ctx, `INSERT INTO runs (name, inactive_after, status, settings, scope, definition_id, schedule, started_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING `+runColumns,
			name, d.InactiveAfter, inventory.RunRunning, settings, scope, defID, schedule, at)); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE scan_definitions SET last_run_at = $2 WHERE id = $1`, defID, at)
		return err
	})
	if uniqueViolation(err) {
		err = ErrRunOpen
	}
	if err != nil {
		return Run{}, fmt.Errorf("start run of scan %d: %w", defID, err)
	}
	return run, nil
}

func (s *Store) LastFullRunAt(ctx context.Context, defID int64) (*time.Time, error) {
	var at *time.Time
	if err := s.db.Pool.QueryRow(ctx, `SELECT max(started_at) FROM runs
		WHERE definition_id = $1 AND COALESCE(settings->>'mode', '') <> $2`, defID, inventory.ModeRecheck).Scan(&at); err != nil {
		return nil, fmt.Errorf("last full run of scan %d: %w", defID, err)
	}
	return at, nil
}

func (s *Store) LatestCompletedRun(ctx context.Context, defID int64) (Run, bool, error) {
	r, err := s.scanRun(s.db.Pool.QueryRow(ctx, `SELECT `+runColumns+` FROM runs
		WHERE definition_id = $1 AND status = 'completed' ORDER BY id DESC LIMIT 1`, defID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, false, nil
	}
	if err != nil {
		return Run{}, false, fmt.Errorf("latest completed run of scan %d: %w", defID, err)
	}
	return r, true, nil
}

func (s *Store) OpenRun(ctx context.Context, defID int64) (Run, bool, error) {
	r, err := s.scanRun(s.db.Pool.QueryRow(ctx, `SELECT `+runColumns+` FROM runs
		WHERE definition_id = $1 AND status IN ('running', 'paused')`, defID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, false, nil
	}
	if err != nil {
		return Run{}, false, fmt.Errorf("open run of scan %d: %w", defID, err)
	}
	return r, true, nil
}

func (s *Store) Run(ctx context.Context, id int64) (Run, error) {
	r, err := s.scanRun(s.db.Pool.QueryRow(ctx, `SELECT `+runColumns+` FROM runs WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, fmt.Errorf("%w: id %d", ErrUnknownRun, id)
	}
	if err != nil {
		return Run{}, fmt.Errorf("read run %d: %w", id, err)
	}
	return r, nil
}

func (s *Store) Runs(ctx context.Context, defID int64, limit int) ([]Run, error) {
	rows, err := s.db.Pool.Query(ctx, `SELECT `+runColumns+` FROM runs WHERE definition_id = $1 ORDER BY id DESC LIMIT $2`, defID, limit)
	if err != nil {
		return nil, fmt.Errorf("list runs of scan %d: %w", defID, err)
	}
	runs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Run, error) { return s.scanRun(row) })
	if err != nil {
		return nil, fmt.Errorf("list runs of scan %d: %w", defID, err)
	}
	return runs, nil
}

func (s *Store) setHeld(ctx context.Context, actor auth.Actor, run Run, held bool) error {
	action := auditResume
	if held {
		action = auditPause
	}
	err := s.db.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE runs SET held = $2 WHERE id = $1`, run.ID, held); err != nil {
			return err
		}
		return writeAudit(ctx, tx, actor, action, run.Name)
	})
	if err != nil {
		return fmt.Errorf("%s run %q: %w", action, run.Name, err)
	}
	return nil
}

func (s *Store) PauseStalled(ctx context.Context, runID int64) (bool, error) {
	tag, err := s.db.Pool.Exec(ctx, `UPDATE runs SET status = 'paused' WHERE id = $1 AND `+stalled, runID)
	if err != nil {
		return false, fmt.Errorf("pause stalled run %d: %w", runID, err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) PauseOrphans(ctx context.Context) (int64, error) {
	tag, err := s.db.Pool.Exec(ctx, `UPDATE runs SET status = 'paused' WHERE status = 'running' AND definition_id IS NOT NULL`)
	if err != nil {
		return 0, fmt.Errorf("pause interrupted runs: %w", err)
	}
	return tag.RowsAffected(), nil
}
