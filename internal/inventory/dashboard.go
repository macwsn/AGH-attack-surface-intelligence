package inventory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	DashboardTopHosts = 10
	DashboardFindings = 10
	DashboardCerts    = 20
	AttentionItems    = 5
	slowCandidates    = 200
)

var DashboardFindingKinds = []string{"admin-panel", "staging", "iot"}

type StatusCounts struct {
	Active, Unstable, Inactive int
}

func (c *StatusCounts) Add(s Status) {
	switch s {
	case StatusActive:
		c.Active++
	case StatusUnstable:
		c.Unstable++
	case StatusInactive:
		c.Inactive++
	}
}

type DashboardFinding struct {
	Address     string
	Port        int
	Protocol    string
	Kind        string
	Name        string
	SignatureID string
	Confidence  int
	FirstSeen   time.Time
}

type DashboardCert struct {
	Address    string
	Port       int
	Protocol   string
	Subject    string
	Issuer     string
	NotAfter   time.Time
	SelfSigned bool
}

type RunProgress struct {
	Run            Run
	Groups         int
	Addresses      int
	HostsFound     int
	LastGroupAt    *time.Time
	PreviousRun    string
	ChangesVersion string
}

type Setup struct {
	HasScan         bool
	HasCompletedRun bool
	HasTeam         bool
}

func (s Setup) Done() bool { return s.HasScan && s.HasCompletedRun && s.HasTeam }

type SlowService struct {
	Address  string
	Port     int
	Protocol string
	LatestMS int64
	MedianMS int64
}

type LaterRun struct {
	Kind string
	Run  Run
}

const (
	LaterImport  = "import"
	LaterManual  = "manual"
	LaterRecheck = "recheck"
	LaterRunning = "running"
)

type Dashboard struct {
	Hosts       StatusCounts
	TopHosts    []HostRow
	Findings    []DashboardFinding
	Certs       []DashboardCert
	Latest      *RunProgress
	Setup       Setup
	NewPanels   []DashboardFinding
	Slow        []SlowService
	ChangesTo   *Run
	ChangesFrom *Run
	Later       []LaterRun
}

const currentObservationsSQL = `
WITH cur AS (
	SELECT DISTINCT ON (so.service_id) so.id, so.service_id, so.http
	FROM service_observations so
	ORDER BY so.service_id, so.run_id DESC)`

func (inv *Inventory) Dashboard(ctx context.Context, now time.Time) (Dashboard, error) {
	top, err := inv.ListHosts(ctx, HostQuery{Sort: "interest", Desc: true, PerPage: DashboardTopHosts})
	if err != nil {
		return Dashboard{}, fmt.Errorf("dashboard: %w", err)
	}
	d := Dashboard{TopHosts: top.Hosts, Findings: []DashboardFinding{}, Certs: []DashboardCert{}}
	err = pgx.BeginTxFunc(ctx, inv.db.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := dashboardHostCounts(ctx, tx, &d.Hosts); err != nil {
			return err
		}
		var err error
		if d.Findings, err = dashboardFindings(ctx, tx); err != nil {
			return err
		}
		if d.Certs, err = dashboardCerts(ctx, tx, now); err != nil {
			return err
		}
		if d.Setup, err = dashboardSetup(ctx, tx); err != nil {
			return err
		}
		if d.Latest, err = inv.dashboardProgress(ctx, tx); err != nil {
			return err
		}
		if err := inv.dashboardChanges(ctx, tx, &d); err != nil || d.Latest == nil {
			return err
		}
		if d.NewPanels, err = dashboardNewPanels(ctx, tx, d.Latest.Run.ID); err != nil {
			return err
		}
		d.Slow, err = dashboardSlow(ctx, tx, d.Latest.Run.ID)
		return err
	})
	if err != nil {
		return Dashboard{}, fmt.Errorf("dashboard: %w", err)
	}
	return d, nil
}

func dashboardHostCounts(ctx context.Context, tx pgx.Tx, c *StatusCounts) error {
	rows, err := tx.Query(ctx, `SELECT status, count(*) FROM host_summary GROUP BY status`)
	if err != nil {
		return fmt.Errorf("count hosts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			s Status
			n int
		)
		if err := rows.Scan(&s, &n); err != nil {
			return fmt.Errorf("count hosts: %w", err)
		}
		switch s {
		case StatusActive:
			c.Active = n
		case StatusUnstable:
			c.Unstable = n
		case StatusInactive:
			c.Inactive = n
		}
	}
	return rows.Err()
}

func dashboardFindings(ctx context.Context, tx pgx.Tx) ([]DashboardFinding, error) {
	rows, err := tx.Query(ctx, currentObservationsSQL+`
		SELECT h.address, s.port, s.protocol, f.kind, f.name, f.signature_id, f.confidence,
		       (SELECT min(so2.observed_at) FROM service_observations so2
		        JOIN findings f2 ON f2.service_observation_id = so2.id
		        WHERE so2.service_id = s.id AND f2.signature_id = f.signature_id) AS first_seen
		FROM cur
		JOIN findings f ON f.service_observation_id = cur.id
		JOIN services s ON s.id = cur.service_id
		JOIN hosts h ON h.id = s.host_id
		JOIN host_summary hs ON hs.host_id = h.id AND hs.status <> 'inactive'
		WHERE f.kind = ANY($1)
		ORDER BY first_seen DESC, hs.address, s.port, f.signature_id
		LIMIT $2`, DashboardFindingKinds, DashboardFindings)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	out := []DashboardFinding{}
	for rows.Next() {
		var f DashboardFinding
		if err := rows.Scan(&f.Address, &f.Port, &f.Protocol, &f.Kind, &f.Name, &f.SignatureID, &f.Confidence, &f.FirstSeen); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func dashboardCerts(ctx context.Context, tx pgx.Tx, now time.Time) ([]DashboardCert, error) {
	rows, err := tx.Query(ctx, currentObservationsSQL+`,
	certs AS (
		SELECT cur.service_id, cur.http->'tls' AS tls,
		       NULLIF(cur.http->'tls'->>'not_after', '')::timestamptz AS not_after
		FROM cur WHERE jsonb_typeof(cur.http->'tls') = 'object')
		SELECT h.address, s.port, s.protocol, COALESCE(c.tls->>'subject_cn', ''), COALESCE(c.tls->>'issuer_cn', ''),
		       c.not_after, COALESCE((c.tls->>'self_signed')::boolean, false)
		FROM certs c
		JOIN services s ON s.id = c.service_id
		JOIN hosts h ON h.id = s.host_id
		JOIN host_summary hs ON hs.host_id = h.id AND hs.status <> 'inactive'
		WHERE COALESCE((c.tls->>'self_signed')::boolean, false) OR c.not_after < $1
		ORDER BY c.not_after NULLS LAST, hs.address, s.port
		LIMIT $2`, now.Add(CertExpiringWindow), DashboardCerts)
	if err != nil {
		return nil, fmt.Errorf("query certificates: %w", err)
	}
	defer rows.Close()
	out := []DashboardCert{}
	for rows.Next() {
		var (
			c        DashboardCert
			notAfter *time.Time
		)
		if err := rows.Scan(&c.Address, &c.Port, &c.Protocol, &c.Subject, &c.Issuer, &notAfter, &c.SelfSigned); err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		if notAfter != nil {
			c.NotAfter = *notAfter
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const startedRunSQL = `(r.status <> 'failed' OR EXISTS (SELECT 1 FROM run_groups g WHERE g.run_id = r.id))`

func (inv *Inventory) dashboardProgress(ctx context.Context, tx pgx.Tx) (*RunProgress, error) {
	run, err := inv.scanRun(tx.QueryRow(ctx, `SELECT `+runColumns+` FROM runs r WHERE `+startedRunSQL+` ORDER BY id DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest run: %w", err)
	}
	p := &RunProgress{Run: run}
	var lastObs *time.Time
	err = tx.QueryRow(ctx, `SELECT count(*), COALESCE(sum(address_count), 0), COALESCE(sum(hosts_found), 0), max(completed_at),
			(SELECT max(observed_at) FROM host_observations WHERE run_id = $1)
		FROM run_groups WHERE run_id = $1`, run.ID).Scan(&p.Groups, &p.Addresses, &p.HostsFound, &p.LastGroupAt, &lastObs)
	if err != nil {
		return nil, fmt.Errorf("run progress: %w", err)
	}
	err = tx.QueryRow(ctx, `SELECT name FROM runs r WHERE id < $1 AND `+startedRunSQL+` ORDER BY id DESC LIMIT 1`, run.ID).Scan(&p.PreviousRun)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("previous run: %w", err)
	}
	p.ChangesVersion = fmt.Sprintf("%d/%s/%d/%d/%d/%v/%v", run.ID, p.PreviousRun, p.Groups, p.Addresses, p.HostsFound,
		timeKey(p.LastGroupAt), timeKey(lastObs))
	if run.Status == RunRunning && run.AddressTotal > p.Addresses {
		p.Addresses = min(p.Addresses+run.InFlight, run.AddressTotal)
	}
	return p, nil
}

const completedScanSQL = `SELECT ` + runColumns + ` FROM runs
	WHERE source = 'scan' AND status = 'completed' AND COALESCE(settings->>'mode', '') <> 'recheck'`

func (inv *Inventory) dashboardChanges(ctx context.Context, tx pgx.Tx, d *Dashboard) error {
	to, err := inv.scanRun(tx.QueryRow(ctx, completedScanSQL+` ORDER BY id DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return inv.dashboardLater(ctx, tx, d, 0)
	}
	if err != nil {
		return fmt.Errorf("latest completed scan: %w", err)
	}
	d.ChangesTo = &to
	from, err := inv.scanRun(tx.QueryRow(ctx, completedScanSQL+` AND id < $1 ORDER BY id DESC LIMIT 1`, to.ID))
	if err == nil {
		d.ChangesFrom = &from
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("previous completed scan: %w", err)
	}
	return inv.dashboardLater(ctx, tx, d, to.ID)
}

func (inv *Inventory) dashboardLater(ctx context.Context, tx pgx.Tx, d *Dashboard, after int64) error {
	for _, q := range []struct{ kind, where string }{
		{LaterImport, `source = 'import' AND status = 'completed'`},
		{LaterManual, `source = 'manual' AND status = 'completed'`},
		{LaterRecheck, `source = 'scan' AND status = 'completed' AND settings->>'mode' = 'recheck'`},
		{LaterRunning, `status IN ('running', 'paused')`},
	} {
		run, err := inv.scanRun(tx.QueryRow(ctx, `SELECT `+runColumns+` FROM runs WHERE id > $1 AND `+q.where+` ORDER BY id DESC LIMIT 1`, after))
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("latest %s run: %w", q.kind, err)
		}
		d.Later = append(d.Later, LaterRun{Kind: q.kind, Run: run})
	}
	return nil
}

func timeKey(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.UnixNano()
}

func dashboardSetup(ctx context.Context, tx pgx.Tx) (Setup, error) {
	var st Setup
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scan_definitions),
			EXISTS (SELECT 1 FROM runs WHERE status = 'completed'),
			EXISTS (SELECT 1 FROM users OFFSET 1) OR EXISTS (SELECT 1 FROM roles WHERE NOT builtin)`).
		Scan(&st.HasScan, &st.HasCompletedRun, &st.HasTeam)
	if err != nil {
		return Setup{}, fmt.Errorf("first-run steps: %w", err)
	}
	return st, nil
}

func dashboardNewPanels(ctx context.Context, tx pgx.Tx, runID int64) ([]DashboardFinding, error) {
	rows, err := tx.Query(ctx, `SELECT h.address, s.port, s.protocol, f.kind, f.name, f.signature_id, f.confidence, so.observed_at
		FROM service_observations so
		JOIN findings f ON f.service_observation_id = so.id
		JOIN services s ON s.id = so.service_id
		JOIN hosts h ON h.id = s.host_id
		WHERE so.run_id = $1 AND f.kind = 'admin-panel'
		  AND NOT EXISTS (SELECT 1 FROM service_observations p
		                  JOIN findings pf ON pf.service_observation_id = p.id
		                  WHERE p.service_id = so.service_id AND p.run_id < $1 AND pf.signature_id = f.signature_id)
		ORDER BY h.address, s.port, s.protocol, f.signature_id
		LIMIT $2`, runID, AttentionItems+1)
	if err != nil {
		return nil, fmt.Errorf("query new admin panels: %w", err)
	}
	defer rows.Close()
	out := []DashboardFinding{}
	for rows.Next() {
		var f DashboardFinding
		if err := rows.Scan(&f.Address, &f.Port, &f.Protocol, &f.Kind, &f.Name, &f.SignatureID, &f.Confidence, &f.FirstSeen); err != nil {
			return nil, fmt.Errorf("scan new admin panel: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func dashboardSlow(ctx context.Context, tx pgx.Tx, runID int64) ([]SlowService, error) {
	rows, err := tx.Query(ctx, `WITH cand AS (
			SELECT so.service_id, (so.http->>'response_time_ms')::bigint AS latest
			FROM service_observations so
			WHERE so.run_id = $1 AND so.http ? 'response_time_ms' AND (so.http->>'response_time_ms')::bigint > $2
			ORDER BY latest DESC, so.service_id
			LIMIT $3)
		SELECT h.address, s.port, s.protocol, c.latest,
		       ARRAY(SELECT (w.http->>'response_time_ms')::bigint FROM service_observations w
		             WHERE w.service_id = c.service_id AND w.run_id <= $1 AND w.http ? 'response_time_ms'
		             ORDER BY w.run_id DESC LIMIT $4)
		FROM cand c
		JOIN services s ON s.id = c.service_id
		JOIN hosts h ON h.id = s.host_id
		ORDER BY c.latest DESC, h.address, s.port`, runID, SlowMinMS, slowCandidates, TimingWindow)
	if err != nil {
		return nil, fmt.Errorf("query slow services: %w", err)
	}
	defer rows.Close()
	out := []SlowService{}
	for rows.Next() {
		var (
			sl     SlowService
			window []int64
		)
		if err := rows.Scan(&sl.Address, &sl.Port, &sl.Protocol, &sl.LatestMS, &window); err != nil {
			return nil, fmt.Errorf("scan slow service: %w", err)
		}
		sl.MedianMS = Median(window)
		if SlowerThanUsual(sl.LatestMS, sl.MedianMS) && len(out) <= AttentionItems {
			out = append(out, sl)
		}
	}
	return out, rows.Err()
}
