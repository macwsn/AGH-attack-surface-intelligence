package inventory

import (
	"context"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
)

type summaryRow struct {
	ports                                        []int32
	services, technologies, findingKinds, titles []string
}

func summarize(h ExportHost) summaryRow {
	ports := map[int32]bool{}
	sets := [4]map[string]bool{{}, {}, {}, {}}
	add := func(i int, v string) {
		if v != "" {
			sets[i][v] = true
		}
	}
	for _, s := range h.Services {
		if s.Status == StatusInactive && !s.LastSeen.Equal(h.LastSeen) {
			continue
		}
		ports[int32(s.Port)] = true
		add(0, s.Service)
		for _, t := range s.Technologies {
			add(1, t.Name)
		}
		for _, f := range s.Findings {
			add(2, f.Kind)
		}
		if s.HTTP != nil {
			add(3, s.HTTP.Title)
		}
	}
	var r summaryRow
	r.ports = make([]int32, 0, len(ports))
	for p := range ports {
		r.ports = append(r.ports, p)
	}
	sort.Slice(r.ports, func(a, b int) bool { return r.ports[a] < r.ports[b] })
	keys := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	r.services, r.technologies, r.findingKinds, r.titles = keys(sets[0]), keys(sets[1]), keys(sets[2]), keys(sets[3])
	return r
}

func (inv *Inventory) RefreshSummary(ctx context.Context) error {
	err := inv.db.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM host_summary`); err != nil {
			return fmt.Errorf("clear: %w", err)
		}
		return inv.refreshSummary(ctx, tx, nil)
	})
	if err != nil {
		return fmt.Errorf("refresh host summary: %w", err)
	}
	if _, err := inv.db.Pool.Exec(ctx, `ANALYZE host_summary`); err != nil {
		return fmt.Errorf("analyze host summary: %w", err)
	}
	return nil
}

func (inv *Inventory) refreshSummary(ctx context.Context, tx pgx.Tx, addresses []string) error {
	q := `SELECT h.id, h.address, (SELECT max(c.run_id) FROM run_group_addresses c WHERE c.address = h.address) FROM hosts h`
	var args []any
	if addresses != nil {
		q, args = q+` WHERE h.address = ANY($1)`, []any{addresses}
	}
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("find hosts to summarise: %w", err)
	}
	var (
		ids    []int64
		byAddr = map[string]int64{}
		byRun  = map[int64][]int64{}
	)
	for rows.Next() {
		var (
			id    int64
			addr  string
			runID *int64
		)
		if err := rows.Scan(&id, &addr, &runID); err != nil {
			rows.Close()
			return fmt.Errorf("scan host to summarise: %w", err)
		}
		ids = append(ids, id)
		byAddr[addr] = id
		if runID != nil {
			byRun[*runID] = append(byRun[*runID], id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("find hosts to summarise: %w", err)
	}
	if len(ids) == 0 {
		return nil
	}
	if addresses != nil {
		if _, err := tx.Exec(ctx, `DELETE FROM host_summary WHERE host_id = ANY($1)`, ids); err != nil {
			return fmt.Errorf("clear summary rows: %w", err)
		}
	}
	runIDs := make([]int64, 0, len(byRun))
	for id := range byRun {
		runIDs = append(runIDs, id)
	}
	sort.Slice(runIDs, func(a, b int) bool { return runIDs[a] < runIDs[b] })
	for _, runID := range runIDs {
		run, err := inv.scanRun(tx.QueryRow(ctx, `SELECT `+runColumns+` FROM runs WHERE id = $1`, runID))
		if err != nil {
			return fmt.Errorf("look up run %d: %w", runID, err)
		}
		hosts, err := inv.loadHosts(ctx, tx, run, byRun[runID])
		if err != nil {
			return fmt.Errorf("load hosts as of run %q: %w", run.Name, err)
		}
		b := &pgx.Batch{}
		for _, h := range hosts {
			r := summarize(h)
			b.Queue(`INSERT INTO host_summary (host_id, address, last_run_id, status, missed_runs, stability, interest_score,
					ports, services, technologies, finding_kinds, titles, hostnames, first_seen, last_seen)
				VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
				ON CONFLICT (host_id) DO UPDATE SET address = EXCLUDED.address, last_run_id = EXCLUDED.last_run_id,
					status = EXCLUDED.status, missed_runs = EXCLUDED.missed_runs, stability = EXCLUDED.stability,
					interest_score = EXCLUDED.interest_score, ports = EXCLUDED.ports, services = EXCLUDED.services,
					technologies = EXCLUDED.technologies, finding_kinds = EXCLUDED.finding_kinds, titles = EXCLUDED.titles,
					hostnames = EXCLUDED.hostnames, first_seen = EXCLUDED.first_seen, last_seen = EXCLUDED.last_seen`,
				byAddr[h.Address], h.Address, run.ID, string(h.Status), h.MissedRuns, h.Stability, h.InterestScore,
				r.ports, r.services, r.technologies, r.findingKinds, r.titles, nonNil(h.Hostnames), h.FirstSeen, h.LastSeen)
		}
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return fmt.Errorf("write summary rows as of run %q: %w", run.Name, err)
		}
	}
	return nil
}

func (inv *Inventory) BackfillSummary(ctx context.Context) (int, error) {
	var addresses []string
	err := inv.db.Tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(h.address), '{}') FROM hosts h
			LEFT JOIN host_summary s ON s.host_id = h.id
			WHERE EXISTS (SELECT 1 FROM host_observations o WHERE o.host_id = h.id)
				AND (s.host_id IS NULL OR s.last_run_id <
					(SELECT max(c.run_id) FROM run_group_addresses c WHERE c.address = h.address))`).Scan(&addresses); err != nil {
			return fmt.Errorf("find stale summary rows: %w", err)
		}
		if len(addresses) == 0 {
			return nil
		}
		return inv.refreshSummary(ctx, tx, addresses)
	})
	if err != nil {
		return 0, fmt.Errorf("backfill host summary: %w", err)
	}
	if len(addresses) > 0 {
		if _, err := inv.db.Pool.Exec(ctx, `ANALYZE host_summary`); err != nil {
			return 0, fmt.Errorf("analyze host summary: %w", err)
		}
	}
	return len(addresses), nil
}
