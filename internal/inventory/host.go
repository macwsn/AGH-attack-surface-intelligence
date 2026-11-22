package inventory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type HostDetail struct {
	Run     string
	Host    ExportHost
	History []HostRunEntry
}

type HostRunEntry struct {
	Run       string
	StartedAt time.Time
	Seen      bool
	Services  []string
	Notes     []string
}

func (inv *Inventory) HostDetail(ctx context.Context, address string) (HostDetail, error) {
	addr, err := normalizeAddress(address)
	if err != nil {
		return HostDetail{}, fmt.Errorf("%w: %w", ErrUnknownHost, err)
	}
	var d HostDetail
	err = pgx.BeginTxFunc(ctx, inv.db.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var hostID int64
		err := tx.QueryRow(ctx, `SELECT id FROM hosts WHERE address = $1`, addr).Scan(&hostID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrUnknownHost, addr)
		}
		if err != nil {
			return fmt.Errorf("look up host: %w", err)
		}
		run, ok, err := inv.runByName(ctx, tx, "")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownHost, addr)
		}
		hosts, err := inv.loadHosts(ctx, tx, run, []int64{hostID})
		if err != nil {
			return err
		}
		if len(hosts) == 0 {
			return fmt.Errorf("%w: %s", ErrUnknownHost, addr)
		}
		d.Run, d.Host = run.Name, hosts[0]
		d.History, err = hostHistory(ctx, tx, addr, hostID)
		return err
	})
	if err != nil {
		return HostDetail{}, fmt.Errorf("host detail of %s: %w", address, err)
	}
	return d, nil
}

func hostHistory(ctx context.Context, tx pgx.Tx, addr string, hostID int64) ([]HostRunEntry, error) {
	rows, err := tx.Query(ctx, `SELECT r.name, r.started_at, ho.host_id IS NOT NULL,
			COALESCE((SELECT array_agg(s.port || '/' || s.protocol ORDER BY s.port, s.protocol)
			          FROM service_observations so JOIN services s ON s.id = so.service_id
			          WHERE so.run_id = c.run_id AND s.host_id = $2), '{}'),
			COALESCE(ho.notes, '{}')
		FROM run_group_addresses c
		JOIN runs r ON r.id = c.run_id
		LEFT JOIN host_observations ho ON ho.run_id = c.run_id AND ho.host_id = $2
		WHERE c.address = $1
		ORDER BY c.run_id DESC`, addr, hostID)
	if err != nil {
		return nil, fmt.Errorf("query history: %w", err)
	}
	defer rows.Close()
	history := []HostRunEntry{}
	for rows.Next() {
		var e HostRunEntry
		if err := rows.Scan(&e.Run, &e.StartedAt, &e.Seen, &e.Services, &e.Notes); err != nil {
			return nil, fmt.Errorf("scan history: %w", err)
		}
		e.Services = nonNil(e.Services)
		e.Notes = nonNil(e.Notes)
		history = append(history, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query history: %w", err)
	}
	return history, nil
}
