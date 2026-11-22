package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/jackc/pgx/v5"
)

var ErrNoRecheckBase = errors.New("no earlier run to recheck")

func (inv *Inventory) SetRunPackets(ctx context.Context, runID int64, packets int) error {
	return inv.updatePackets(ctx, runID, packets, `UPDATE runs SET packets = $2 WHERE id = $1`)
}

func (inv *Inventory) AddRunPackets(ctx context.Context, runID int64, packets int) error {
	return inv.updatePackets(ctx, runID, packets, `UPDATE runs SET packets = packets + $2 WHERE id = $1`)
}

func (inv *Inventory) updatePackets(ctx context.Context, runID int64, packets int, q string) error {
	if packets < 0 {
		return fmt.Errorf("inventory: negative packet count %d", packets)
	}
	tag, err := inv.db.Pool.Exec(ctx, q, runID, packets)
	if err != nil {
		return fmt.Errorf("update packets of run %d: %w", runID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: id %d", ErrUnknownRun, runID)
	}
	return nil
}

func (inv *Inventory) RecheckBase(ctx context.Context, run Run) (Run, error) {
	var base Run
	err := pgx.BeginTxFunc(ctx, inv.db.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		defID := run.DefinitionID
		if run.ID > 0 {
			err := tx.QueryRow(ctx, `SELECT COALESCE(definition_id, 0) FROM runs WHERE id = $1`, run.ID).Scan(&defID)
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: id %d", ErrUnknownRun, run.ID)
			}
			if err != nil {
				return fmt.Errorf("look up definition of run %d: %w", run.ID, err)
			}
		}
		var (
			r   Run
			err error
		)
		if defID > 0 {
			r, err = inv.scanRun(tx.QueryRow(ctx, `SELECT `+runColumns+` FROM runs
				WHERE definition_id = $1 AND status = 'completed' AND ($2 = 0 OR id < $2)
				ORDER BY id DESC LIMIT 1`, defID, run.ID))
		} else {
			r, err = inv.sameScopeRun(ctx, tx, run)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			if defID > 0 {
				return fmt.Errorf("%w: no completed run of the scan definition", ErrNoRecheckBase)
			}
			return fmt.Errorf("%w: no completed run with the same targets and excludes", ErrNoRecheckBase)
		}
		if err != nil {
			return fmt.Errorf("look up recheck base: %w", err)
		}
		base = r
		return nil
	})
	if err != nil {
		return Run{}, fmt.Errorf("recheck base: %w", err)
	}
	return base, nil
}

func (inv *Inventory) sameScopeRun(ctx context.Context, tx pgx.Tx, run Run) (Run, error) {
	targets, excludes := sortedCopy(run.Settings.Targets), sortedCopy(run.Settings.Excludes)
	rows, err := tx.Query(ctx, `SELECT `+runColumns+` FROM runs
		WHERE status = 'completed' AND ($1 = 0 OR id < $1) ORDER BY id DESC`, run.ID)
	if err != nil {
		return Run{}, err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := inv.scanRun(rows)
		if err != nil {
			return Run{}, err
		}
		if slices.Equal(sortedCopy(r.Settings.Targets), targets) && slices.Equal(sortedCopy(r.Settings.Excludes), excludes) {
			return r, nil
		}
	}
	if err := rows.Err(); err != nil {
		return Run{}, err
	}
	return Run{}, pgx.ErrNoRows
}

func (inv *Inventory) KnownServices(ctx context.Context, base Run, ports []int, inScope func(address string) bool) ([]KnownService, error) {
	var hosts []ExportHost
	err := pgx.BeginTxFunc(ctx, inv.db.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		hosts, err = inv.loadHosts(ctx, tx, base, nil)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("known services as of run %q: %w", base.Name, err)
	}
	out := []KnownService{}
	for _, h := range hosts {
		if inScope != nil && !inScope(h.Address) {
			continue
		}
		for _, s := range h.Services {
			if s.Protocol != "tcp" || (s.Status != StatusActive && s.Status != StatusUnstable) {
				continue
			}
			if len(ports) > 0 && !slices.Contains(ports, s.Port) {
				continue
			}
			out = append(out, KnownService{Address: h.Address, Port: s.Port, Protocol: s.Protocol, Service: s.Service, HTTP: s.HTTP != nil})
		}
	}
	return out, nil
}

func (inv *Inventory) RecheckPlan(ctx context.Context, run Run, inScope func(address string) bool) (Run, []KnownService, error) {
	base, err := inv.RecheckBase(ctx, run)
	if err != nil {
		return Run{}, nil, err
	}
	known, err := inv.KnownServices(ctx, base, run.Settings.Ports, inScope)
	if err != nil {
		return Run{}, nil, err
	}
	if len(run.Settings.Hosts) > 0 {
		order := map[string]int{}
		for i, a := range run.Settings.Hosts {
			addr, err := normalizeAddress(a)
			if err != nil {
				return Run{}, nil, fmt.Errorf("recheck hosts: %w", err)
			}
			if _, dup := order[addr]; !dup {
				order[addr] = i
			}
		}
		picked := known[:0]
		for _, k := range known {
			if _, ok := order[k.Address]; ok {
				picked = append(picked, k)
			}
		}
		known = picked
		sort.SliceStable(known, func(a, b int) bool { return order[known[a].Address] < order[known[b].Address] })
	}
	if len(known) == 0 {
		return Run{}, nil, fmt.Errorf("recheck base: %w: run %q has no known open service in scope", ErrNoRecheckBase, base.Name)
	}
	return base, known, nil
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}
