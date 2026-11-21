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
	DefinitionID int64
	Held         bool
	Schedule     Schedule
	AddressTotal int
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
	} else if _, err := targets.Parse(strings.NewReader(strings.Join(st.Targets, "\n"))); err != nil {
		errs = append(errs, fmt.Errorf("targets: %w", err))
	}
	if _, err := targets.Parse(strings.NewReader(strings.Join(st.Excludes, "\n"))); err != nil {
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
	if st.MaxRate < 1 {
		errs = append(errs, errors.New("max rate: enter at least 1 per second"))
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
	add("timezone", a.Schedule.Timezone, b.Schedule.Timezone)
	add("windows", a.Schedule.Windows, b.Schedule.Windows)
	add("frequency", a.Schedule.Frequency, b.Schedule.Frequency)
	return out
}

type Store struct {
	db *store.Store
}

func NewStore(db *store.Store) *Store { return &Store{db: db} }

const defColumns = `id, name, enabled, inactive_after, settings, schedule, last_run_at, updated_at`

func scanDefinition(row pgx.Row) (Definition, error) {
	var (
		d                  Definition
		settings, schedule []byte
	)
	if err := row.Scan(&d.ID, &d.Name, &d.Enabled, &d.InactiveAfter, &settings, &schedule, &d.LastRunAt, &d.UpdatedAt); err != nil {
		return Definition{}, err
	}
	if err := json.Unmarshal(settings, &d.Settings); err != nil {
		return Definition{}, fmt.Errorf("decode settings of scan %q: %w", d.Name, err)
	}
	if err := json.Unmarshal(schedule, &d.Schedule); err != nil {
		return Definition{}, fmt.Errorf("decode schedule of scan %q: %w", d.Name, err)
	}
	return d, nil
}

const runColumns = `id, name, inactive_after, started_at, finished_at, status, settings,
	COALESCE(definition_id, 0), held, COALESCE(schedule, '{}'), COALESCE(address_total, 0)`

func scanRun(row pgx.Row) (Run, error) {
	var (
		r                  Run
		settings, schedule []byte
	)
	if err := row.Scan(&r.ID, &r.Name, &r.InactiveAfter, &r.StartedAt, &r.FinishedAt, &r.Status, &settings,
		&r.DefinitionID, &r.Held, &schedule, &r.AddressTotal); err != nil {
		return Run{}, err
	}
	if err := json.Unmarshal(settings, &r.Settings); err != nil {
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
	defs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Definition, error) { return scanDefinition(row) })
	if err != nil {
		return nil, fmt.Errorf("list scan definitions: %w", err)
	}
	return defs, nil
}

func (s *Store) Definition(ctx context.Context, id int64) (Definition, error) {
	d, err := scanDefinition(s.db.Pool.QueryRow(ctx, `SELECT `+defColumns+` FROM scan_definitions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Definition{}, fmt.Errorf("%w: id %d", ErrUnknownDefinition, id)
	}
	if err != nil {
		return Definition{}, fmt.Errorf("read scan definition %d: %w", id, err)
	}
	return d, nil
}

func encode(d Definition) (settings, schedule string, err error) {
	if d.Schedule.Windows == nil {
		d.Schedule.Windows = []Window{}
	}
	a, err := json.Marshal(d.Settings)
	if err != nil {
		return "", "", fmt.Errorf("encode settings: %w", err)
	}
	b, err := json.Marshal(d.Schedule)
	if err != nil {
		return "", "", fmt.Errorf("encode schedule: %w", err)
	}
	return string(a), string(b), nil
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
	settings, schedule, err := encode(d)
	if err != nil {
		return Definition{}, err
	}
	var out Definition
	err = s.db.Tx(ctx, func(tx pgx.Tx) error {
		out, err = scanDefinition(tx.QueryRow(ctx, `INSERT INTO scan_definitions (name, enabled, inactive_after, settings, schedule)
			VALUES ($1, $2, $3, $4, $5) RETURNING `+defColumns, d.Name, d.Enabled, d.InactiveAfter, settings, schedule))
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
	settings, schedule, err := encode(d)
	if err != nil {
		return Definition{}, err
	}
	var out Definition
	err = s.db.Tx(ctx, func(tx pgx.Tx) error {
		old, err := scanDefinition(tx.QueryRow(ctx, `SELECT `+defColumns+` FROM scan_definitions WHERE id = $1 FOR UPDATE`, d.ID))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: id %d", ErrUnknownDefinition, d.ID)
		}
		if err != nil {
			return err
		}
		changed := changedFields(old, d)
		if out, err = scanDefinition(tx.QueryRow(ctx, `UPDATE scan_definitions SET name = $2, inactive_after = $3,
				settings = $4, schedule = $5, updated_at = now() WHERE id = $1 RETURNING `+defColumns,
			d.ID, d.Name, d.InactiveAfter, settings, schedule)); err != nil {
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

func (s *Store) StartRun(ctx context.Context, defID int64, at time.Time) (Run, error) {
	var run Run
	err := s.db.Tx(ctx, func(tx pgx.Tx) error {
		d, err := scanDefinition(tx.QueryRow(ctx, `SELECT `+defColumns+` FROM scan_definitions WHERE id = $1 FOR UPDATE`, defID))
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
		settings, schedule, err := encode(d)
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
		if run, err = scanRun(tx.QueryRow(ctx, `INSERT INTO runs (name, inactive_after, status, settings, definition_id, schedule)
				VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+runColumns,
			name, d.InactiveAfter, inventory.RunRunning, settings, defID, schedule)); err != nil {
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

func (s *Store) OpenRun(ctx context.Context, defID int64) (Run, bool, error) {
	r, err := scanRun(s.db.Pool.QueryRow(ctx, `SELECT `+runColumns+` FROM runs
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
	r, err := scanRun(s.db.Pool.QueryRow(ctx, `SELECT `+runColumns+` FROM runs WHERE id = $1`, id))
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
	runs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Run, error) { return scanRun(row) })
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

func (s *Store) PauseOrphans(ctx context.Context) (int64, error) {
	tag, err := s.db.Pool.Exec(ctx, `UPDATE runs SET status = 'paused' WHERE status = 'running' AND definition_id IS NOT NULL`)
	if err != nil {
		return 0, fmt.Errorf("pause interrupted runs: %w", err)
	}
	return tag.RowsAffected(), nil
}
