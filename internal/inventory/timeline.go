package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

const TimelineRuns = 50

type TimelineEntry struct {
	Run     Run
	At      time.Time
	Covered bool
	Seen    bool
	State   *ExportHost
}

type Timeline struct {
	Address  string
	Host     ExportHost
	Score    int
	Reasons  []Reason
	Pattern  Pattern
	Usual    bool
	Entries  []TimelineEntry
	LatestAt time.Time

	VolatileHeaders []string
}

func (inv *Inventory) HostTimeline(ctx context.Context, address string) (Timeline, error) {
	tl := Timeline{Address: address, VolatileHeaders: inv.VolatileHeaders}
	err := pgx.BeginTxFunc(ctx, inv.db.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var hostID int64
		err := tx.QueryRow(ctx, `SELECT id FROM hosts WHERE address = $1`, address).Scan(&hostID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrUnknownHost, address)
		}
		if err != nil {
			return fmt.Errorf("look up host %s: %w", address, err)
		}
		rows, err := tx.Query(ctx, `SELECT `+runColumns+` FROM runs ORDER BY id DESC LIMIT $1`, TimelineRuns)
		if err != nil {
			return fmt.Errorf("list runs: %w", err)
		}
		runs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Run, error) { return inv.scanRun(row) })
		if err != nil {
			return fmt.Errorf("list runs: %w", err)
		}
		slices.Reverse(runs)
		ids := make([]int64, len(runs))
		for i, r := range runs {
			ids[i] = r.ID
		}
		covered := map[int64]time.Time{}
		rows, err = tx.Query(ctx, `SELECT c.run_id, g.completed_at FROM run_group_addresses c
			JOIN run_groups g ON g.run_id = c.run_id AND g.group_index = c.group_index
			WHERE c.address = $1 AND c.run_id = ANY($2)`, address, ids)
		if err != nil {
			return fmt.Errorf("coverage of %s: %w", address, err)
		}
		var (
			id int64
			at time.Time
		)
		_, err = pgx.ForEachRow(rows, []any{&id, &at}, func() error { covered[id] = at; return nil })
		if err != nil {
			return fmt.Errorf("coverage of %s: %w", address, err)
		}
		seen := map[int64]bool{}
		rows, err = tx.Query(ctx, `SELECT run_id FROM host_observations WHERE host_id = $1 AND run_id = ANY($2)`, hostID, ids)
		if err != nil {
			return fmt.Errorf("observations of %s: %w", address, err)
		}
		_, err = pgx.ForEachRow(rows, []any{&id}, func() error { seen[id] = true; return nil })
		if err != nil {
			return fmt.Errorf("observations of %s: %w", address, err)
		}
		for i, r := range runs {
			e := TimelineEntry{Run: r, At: r.StartedAt, Seen: seen[r.ID]}
			if t, ok := covered[r.ID]; ok {
				e.Covered, e.At = true, t
			}
			if e.Covered || i == len(runs)-1 {
				hosts, err := inv.loadHostsAt(ctx, tx, r, address)
				if err != nil {
					return err
				}
				if len(hosts) == 1 {
					e.State = &hosts[0]
				}
			}
			tl.Entries = append(tl.Entries, e)
		}
		return nil
	})
	if err != nil {
		return Timeline{}, fmt.Errorf("timeline of %s: %w", address, err)
	}
	var obs []PresenceObservation
	for _, e := range tl.Entries {
		obs = append(obs, PresenceObservation{At: e.At, Covered: e.Covered, Seen: e.Seen})
	}
	tl.Pattern, tl.Usual = TimeOfDay(obs, nil)
	if n := len(tl.Entries); n > 0 && tl.Entries[n-1].State != nil {
		last := tl.Entries[n-1]
		tl.Host = *last.State
		tl.LatestAt = last.Run.StartedAt
		tl.Score, tl.Reasons = Score(tl.Host, last.Run.StartedAt, inv.Interest)
		tl.Host.InterestScore = tl.Score
	} else {
		tl.Host = ExportHost{Address: address, Status: StatusInactive}
		tl.Reasons = []Reason{}
	}
	return tl, nil
}
