package inventory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"asi/internal/probe"
)

func validRunStatus(s RunStatus) bool {
	switch s {
	case RunRunning, RunPaused, RunCompleted, RunFailed:
		return true
	}
	return false
}

func (inv *Inventory) RunByName(ctx context.Context, name string) (Run, error) {
	var run Run
	err := pgx.BeginTxFunc(ctx, inv.db.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		r, ok, err := inv.runByName(ctx, tx, name)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: no runs recorded", ErrUnknownRun)
		}
		run = r
		return nil
	})
	if err != nil {
		return Run{}, err
	}
	return run, nil
}

func (inv *Inventory) SetRunStatus(ctx context.Context, runID int64, status RunStatus) error {
	if !validRunStatus(status) {
		return fmt.Errorf("inventory: invalid run status %q", status)
	}
	finished := status == RunCompleted || status == RunFailed
	tag, err := inv.db.Pool.Exec(ctx, `UPDATE runs SET status = $2,
			finished_at = CASE WHEN $3 THEN now() ELSE NULL END
		WHERE id = $1`, runID, status, finished)
	if err != nil {
		return fmt.Errorf("set status of run %d to %s: %w", runID, status, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: id %d", ErrUnknownRun, runID)
	}
	if finished {
		return inv.pruneBodies(ctx, runID)
	}
	return nil
}

func (inv *Inventory) pruneBodies(ctx context.Context, runID int64) error {
	keep := inv.BodyRetention
	if keep <= 0 {
		keep = DefaultBodyRetention
	}
	if _, err := inv.db.Pool.Exec(ctx, `UPDATE service_observations so SET http_body = NULL
		FROM (SELECT o.service_id, c.run_id AS cutoff FROM service_observations o
			CROSS JOIN LATERAL (SELECT p.run_id FROM service_observations p WHERE p.service_id = o.service_id
				ORDER BY p.run_id DESC OFFSET $2 LIMIT 1) c
			WHERE o.run_id = $1) old
		WHERE so.service_id = old.service_id AND so.run_id <= old.cutoff AND so.http_body IS NOT NULL`, runID, keep); err != nil {
		return fmt.Errorf("prune response bodies after run %d: %w", runID, err)
	}
	return nil
}

func (inv *Inventory) RunGroups(ctx context.Context, runID int64) ([]GroupInfo, error) {
	rows, err := inv.db.Pool.Query(ctx, `SELECT g.group_index, g.address_count, g.hosts_found, g.duration_ns, g.completed_at,
			COALESCE((SELECT array_agg(a.address ORDER BY a.address) FROM run_group_addresses a
			          WHERE a.run_id = g.run_id AND a.group_index = g.group_index), '{}')
		FROM run_groups g WHERE g.run_id = $1 ORDER BY g.group_index`, runID)
	if err != nil {
		return nil, fmt.Errorf("list groups of run %d: %w", runID, err)
	}
	defer rows.Close()
	groups := []GroupInfo{}
	for rows.Next() {
		var (
			g  GroupInfo
			ns int64
		)
		if err := rows.Scan(&g.Index, &g.AddressCount, &g.HostsFound, &ns, &g.CompletedAt, &g.Addresses); err != nil {
			return nil, fmt.Errorf("scan group of run %d: %w", runID, err)
		}
		g.Duration = time.Duration(ns)
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list groups of run %d: %w", runID, err)
	}
	return groups, nil
}

func (inv *Inventory) PreviouslyLiveAddresses(ctx context.Context, runID int64) ([]string, error) {
	var out []string
	err := pgx.BeginTxFunc(ctx, inv.db.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		prev, err := inv.scanRun(tx.QueryRow(ctx, `SELECT `+runColumns+` FROM runs WHERE id < $1 ORDER BY id DESC LIMIT 1`, runID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("look up run before %d: %w", runID, err)
		}
		hosts, err := inv.loadHosts(ctx, tx, prev, nil)
		if err != nil {
			return err
		}
		for _, h := range hosts {
			if h.Status == StatusActive || h.Status == StatusUnstable {
				out = append(out, h.Address)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list live addresses before run %d: %w", runID, err)
	}
	return nonNil(out), nil
}

type FaviconKey struct {
	Address string
	Port    int
}

func (inv *Inventory) PreviousFavicons(ctx context.Context, runID int64) (map[FaviconKey]string, error) {
	rows, err := inv.db.Pool.Query(ctx, `SELECT DISTINCT ON (o.service_id) h.address, s.port, COALESCE(o.http->>'favicon_sha256', '')
		FROM service_observations o
		JOIN services s ON s.id = o.service_id
		JOIN hosts h ON h.id = s.host_id
		WHERE o.run_id < $1 AND s.protocol = 'tcp'
		ORDER BY o.service_id, o.run_id DESC`, runID)
	if err != nil {
		return nil, fmt.Errorf("favicons before run %d: %w", runID, err)
	}
	defer rows.Close()
	out := map[FaviconKey]string{}
	var (
		k   FaviconKey
		sum string
	)
	for rows.Next() {
		if err := rows.Scan(&k.Address, &k.Port, &sum); err != nil {
			return nil, fmt.Errorf("favicons before run %d: %w", runID, err)
		}
		if sum != "" {
			out[k] = sum
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("favicons before run %d: %w", runID, err)
	}
	return out, nil
}

func (inv *Inventory) RecordLateHosts(ctx context.Context, runID int64, hosts []HostResult) error {
	if len(hosts) == 0 {
		return nil
	}
	_, prepared, err := inv.prepareGroup(GroupResult{Hosts: hosts})
	if err != nil {
		return err
	}
	err = inv.db.Tx(ctx, func(tx pgx.Tx) error {
		var id int64
		err := tx.QueryRow(ctx, `SELECT id FROM runs WHERE id = $1 FOR UPDATE`, runID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: id %d", ErrUnknownRun, runID)
		}
		if err != nil {
			return fmt.Errorf("lock run: %w", err)
		}
		for _, h := range prepared {
			var group int
			err := tx.QueryRow(ctx, `SELECT group_index FROM run_group_addresses WHERE run_id = $1 AND address = $2`,
				runID, h.address).Scan(&group)
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("inventory: host %s is not covered by a recorded group of run %d", h.address, runID)
			}
			if err != nil {
				return fmt.Errorf("find group of host %s: %w", h.address, err)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM service_observations so USING services s, hosts h
				WHERE so.run_id = $1 AND so.service_id = s.id AND s.host_id = h.id AND h.address = $2`, runID, h.address); err != nil {
				return fmt.Errorf("replace services of host %s: %w", h.address, err)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM host_observations ho USING hosts h
				WHERE ho.run_id = $1 AND ho.host_id = h.id AND h.address = $2`, runID, h.address); err != nil {
				return fmt.Errorf("replace host %s: %w", h.address, err)
			}
			if err := inv.recordHost(ctx, tx, runID, group, h); err != nil {
				return fmt.Errorf("host %s: %w", h.address, err)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE run_groups g SET hosts_found =
				(SELECT count(*) FROM host_observations o WHERE o.run_id = g.run_id AND o.group_index = g.group_index)
			WHERE g.run_id = $1`, runID); err != nil {
			return fmt.Errorf("update hosts found: %w", err)
		}
		addresses := make([]string, 0, len(prepared))
		for _, h := range prepared {
			addresses = append(addresses, h.address)
		}
		if err := inv.refreshSummary(ctx, tx, addresses); err != nil {
			return fmt.Errorf("refresh host summary: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("record late hosts of run %d: %w", runID, err)
	}
	return nil
}

func (inv *Inventory) ListRuns(ctx context.Context) ([]Run, error) {
	rows, err := inv.db.Pool.Query(ctx, `SELECT `+runColumns+` FROM runs ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()
	runs := []Run{}
	for rows.Next() {
		r, err := inv.scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("list runs: %w", err)
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	return runs, nil
}

func (inv *Inventory) Heartbeat(ctx context.Context, runID int64, inFlight int) error {
	if _, err := inv.db.Pool.Exec(ctx, `UPDATE runs SET heartbeat_at = now(), inflight_addresses = $2 WHERE id = $1`, runID, inFlight); err != nil {
		return fmt.Errorf("heartbeat of run %d: %w", runID, err)
	}
	return nil
}

func (inv *Inventory) SetRunTotal(ctx context.Context, runID int64, total int) error {
	if total < 0 {
		return fmt.Errorf("inventory: negative address total %d", total)
	}
	tag, err := inv.db.Pool.Exec(ctx, `UPDATE runs SET address_total = $2 WHERE id = $1`, runID, total)
	if err != nil {
		return fmt.Errorf("set address total of run %d: %w", runID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: id %d", ErrUnknownRun, runID)
	}
	return nil
}

func (inv *Inventory) RecordFailedGroup(ctx context.Context, runID int64, g FailedGroup) error {
	if g.Index < 0 {
		return fmt.Errorf("inventory: negative group index %d", g.Index)
	}
	addresses := make([]string, 0, len(g.Addresses))
	for _, a := range g.Addresses {
		addr, err := normalizeAddress(a)
		if err != nil {
			return err
		}
		addresses = append(addresses, addr)
	}
	_, err := inv.db.Pool.Exec(ctx, `INSERT INTO run_failed_groups (run_id, group_index, addresses, reason)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (run_id, group_index) DO UPDATE SET addresses = EXCLUDED.addresses, reason = EXCLUDED.reason, failed_at = now()`,
		runID, g.Index, addresses, g.Reason)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return fmt.Errorf("%w: id %d", ErrUnknownRun, runID)
	}
	if err != nil {
		return fmt.Errorf("record failed group %d of run %d: %w", g.Index, runID, err)
	}
	return nil
}

func (inv *Inventory) FailedGroups(ctx context.Context, runID int64) ([]FailedGroup, error) {
	rows, err := inv.db.Pool.Query(ctx, `SELECT group_index, addresses, reason, failed_at
		FROM run_failed_groups WHERE run_id = $1 ORDER BY group_index`, runID)
	if err != nil {
		return nil, fmt.Errorf("list failed groups of run %d: %w", runID, err)
	}
	defer rows.Close()
	groups := []FailedGroup{}
	for rows.Next() {
		var g FailedGroup
		if err := rows.Scan(&g.Index, &g.Addresses, &g.Reason, &g.FailedAt); err != nil {
			return nil, fmt.Errorf("scan failed group of run %d: %w", runID, err)
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list failed groups of run %d: %w", runID, err)
	}
	return groups, nil
}

var ErrUnknownService = errors.New("inventory: unknown service")

func (inv *Inventory) LatestHTTP(ctx context.Context, address string, port int, protocol string) (*probe.HTTP, []byte, string, error) {
	addr, err := normalizeAddress(address)
	if err != nil {
		return nil, nil, "", err
	}
	var (
		run                         string
		doc, headers, cookies, body []byte
	)
	err = inv.db.Pool.QueryRow(ctx, `SELECT r.name, so.http, so.http_headers, so.http_cookies, so.http_body
		FROM service_observations so
		JOIN services s ON s.id = so.service_id
		JOIN hosts h ON h.id = s.host_id
		JOIN runs r ON r.id = so.run_id
		WHERE h.address = $1 AND s.port = $2 AND s.protocol = $3
		ORDER BY so.run_id DESC LIMIT 1`, addr, port, protocol).Scan(&run, &doc, &headers, &cookies, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, "", fmt.Errorf("%w: %s %d/%s", ErrUnknownService, addr, port, protocol)
	}
	if err != nil {
		return nil, nil, "", fmt.Errorf("latest observation of %s %d/%s: %w", addr, port, protocol, err)
	}
	h, err := inv.decodeHTTP(doc, headers, cookies)
	if err != nil {
		return nil, nil, "", fmt.Errorf("latest observation of %s %d/%s: %w", addr, port, protocol, err)
	}
	var plain []byte
	if body != nil {
		if plain, err = inv.open(body); err != nil {
			return nil, nil, "", fmt.Errorf("body of the latest observation of %s %d/%s: %w", addr, port, protocol, err)
		}
		if plain == nil {
			plain = []byte{}
		}
	}
	return h, plain, run, nil
}

func (inv *Inventory) RecordRateSamples(ctx context.Context, runID int64, samples []RateSample) error {
	if len(samples) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, s := range samples {
		if s.Configured < 0 || s.Effective < 0 || s.Sent < 0 || s.Packets < 0 {
			return fmt.Errorf("inventory: negative rate sample %+v", s)
		}
		b.Queue(`INSERT INTO run_rate_samples (run_id, minute, configured_limit, effective_limit, sent, estimated_packets)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (run_id, minute) DO UPDATE SET configured_limit = EXCLUDED.configured_limit,
				effective_limit = GREATEST(run_rate_samples.effective_limit, EXCLUDED.effective_limit),
				sent = run_rate_samples.sent + EXCLUDED.sent,
				estimated_packets = run_rate_samples.estimated_packets + EXCLUDED.estimated_packets`,
			runID, s.Minute.UTC().Truncate(time.Minute), s.Configured, s.Effective, s.Sent, s.Packets)
	}
	err := inv.db.Pool.SendBatch(ctx, b).Close()
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return fmt.Errorf("%w: id %d", ErrUnknownRun, runID)
	}
	if err != nil {
		return fmt.Errorf("record rate samples of run %d: %w", runID, err)
	}
	return nil
}

func (inv *Inventory) RateSamples(ctx context.Context, runID int64) ([]RateSample, error) {
	rows, err := inv.db.Pool.Query(ctx, `SELECT minute, configured_limit, effective_limit, sent, estimated_packets
		FROM run_rate_samples WHERE run_id = $1 ORDER BY minute`, runID)
	if err != nil {
		return nil, fmt.Errorf("list rate samples of run %d: %w", runID, err)
	}
	defer rows.Close()
	out := []RateSample{}
	for rows.Next() {
		var s RateSample
		if err := rows.Scan(&s.Minute, &s.Configured, &s.Effective, &s.Sent, &s.Packets); err != nil {
			return nil, fmt.Errorf("scan rate sample of run %d: %w", runID, err)
		}
		s.Minute = s.Minute.UTC()
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list rate samples of run %d: %w", runID, err)
	}
	return out, nil
}
