package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/detect"
)

const (
	AuditHunt       = "signature.hunt"
	AuditHuntRecord = "signature.hunt.record"
	SourceRetroHunt = "retro-hunt"
	HuntSchema      = "asi.hunt/v1"
	huntBatchSize   = 1000
)

var (
	ErrUnknownHunt = errors.New("inventory: unknown hunt")
	ErrStaleHunt   = errors.New("inventory: a newer run exists than the latest run of the hunt")
)

type HuntSpec struct {
	Signature detect.Signature
	Source    string
	Since     time.Time
	Actor     string
	Addr      string
}

type Hunt struct {
	ID           int64         `json:"id"`
	SignatureID  string        `json:"signature_id"`
	Source       string        `json:"-"`
	Actor        string        `json:"actor"`
	Since        *time.Time    `json:"since,omitempty"`
	LatestRun    string        `json:"latest_run"`
	Observations int           `json:"observations"`
	Matched      int           `json:"matched"`
	InLatest     int           `json:"matches_latest_run"`
	NotEvaluable int           `json:"not_evaluable"`
	Duration     time.Duration `json:"-"`
	CreatedAt    time.Time     `json:"created_at"`
	latestRunID  *int64
}

type HuntResult struct {
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Evaluable bool   `json:"evaluable"`
	FirstRun  string `json:"first_run,omitempty"`
	LastRun   string `json:"last_run,omitempty"`
	InLatest  bool   `json:"matches_latest_run"`
	Version   string `json:"version"`
}

type huntService struct {
	id          int64
	address     string
	port        int
	protocol    string
	evaluable   bool
	matched     bool
	first, last int64
	inLatest    bool
	version     string
	evidence    string
	observed    int64
	covered     int64
}

func (inv *Inventory) RunHunt(ctx context.Context, spec HuntSpec) (Hunt, error) {
	start := time.Now()
	sig := &spec.Signature
	var since *time.Time
	if !spec.Since.IsZero() {
		since = &spec.Since
	}
	var (
		huntID int64
		latest *int64
	)
	source, err := inv.sealString(spec.Source)
	if err != nil {
		return Hunt{}, err
	}
	err = inv.db.Tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT max(id) FROM runs`).Scan(&latest); err != nil {
			return fmt.Errorf("latest run: %w", err)
		}
		if err := tx.QueryRow(ctx, `INSERT INTO hunts (signature_id, source, actor, since, latest_run_id)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`, sig.ID, source, spec.Actor, since, latest).Scan(&huntID); err != nil {
			return fmt.Errorf("insert hunt: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_log (actor, action, target, address) VALUES ($1, $2, $3, $4)`,
			spec.Actor, AuditHunt, sig.ID, spec.Addr); err != nil {
			return fmt.Errorf("write audit %s: %w", AuditHunt, err)
		}
		return nil
	})
	if err != nil {
		return Hunt{}, fmt.Errorf("start hunt for %q: %w", sig.ID, err)
	}
	counts, err := inv.hunt(ctx, huntID, sig, since, latest)
	if err == nil {
		_, err = inv.db.Pool.Exec(ctx, `UPDATE hunts SET observations = $2, matched = $3, not_evaluable = $4, in_latest = $5, duration_ns = $6 WHERE id = $1`,
			huntID, counts[0], counts[1], counts[2], counts[3], time.Since(start).Nanoseconds())
	}
	if err != nil {
		if _, derr := inv.db.Pool.Exec(context.WithoutCancel(ctx), `DELETE FROM hunts WHERE id = $1`, huntID); derr != nil {
			err = errors.Join(err, fmt.Errorf("discard hunt %d: %w", huntID, derr))
		}
		return Hunt{}, fmt.Errorf("hunt for %q: %w", sig.ID, err)
	}
	return inv.GetHunt(ctx, huntID)
}

func (inv *Inventory) hunt(ctx context.Context, huntID int64, sig *detect.Signature, since *time.Time, latest *int64) ([4]int, error) {
	var counts [4]int
	scopeOf, scopeLatest, err := inv.runScopes(ctx, latest)
	if err != nil {
		return counts, err
	}
	needsBody := sig.NeedsBody()
	rows, err := inv.db.Pool.Query(ctx, `SELECT so.service_id, h.address, s.port, s.protocol, so.run_id,
			so.http, so.http_headers, so.http_cookies, CASE WHEN $2 THEN so.http_body END,
			(SELECT max(c.run_id) FROM run_group_addresses c WHERE c.address = h.address AND c.run_id <= $3)
		FROM service_observations so
		JOIN services s ON s.id = so.service_id
		JOIN hosts h ON h.id = s.host_id
		JOIN runs r ON r.id = so.run_id
		WHERE so.http IS NOT NULL AND ($1::timestamptz IS NULL OR r.started_at >= $1)
		ORDER BY so.service_id, so.run_id`, since, needsBody, latest)
	if err != nil {
		return counts, fmt.Errorf("query observations: %w", err)
	}
	defer rows.Close()
	var (
		batch []huntService
		cur   *huntService
	)
	flush := func(force bool) error {
		if cur != nil && cur.matched {
			cur.inLatest = cur.last == max(cur.covered, scopeLatest[scopeOf[cur.observed]])
		}
		if cur != nil && (cur.matched || !cur.evaluable) {
			batch = append(batch, *cur)
			if cur.matched {
				counts[1]++
				if cur.inLatest {
					counts[3]++
				}
			} else {
				counts[2]++
			}
		}
		cur = nil
		if len(batch) >= huntBatchSize || (force && len(batch) > 0) {
			if err := inv.writeHuntResults(ctx, huntID, batch); err != nil {
				return err
			}
			batch = batch[:0]
		}
		return nil
	}
	var (
		svcID, runID                int64
		covering                    *int64
		address, protocol           string
		port                        int
		doc, headers, cookies, body []byte
	)
	for rows.Next() {
		if err := rows.Scan(&svcID, &address, &port, &protocol, &runID, &doc, &headers, &cookies, &body, &covering); err != nil {
			return counts, fmt.Errorf("scan observation: %w", err)
		}
		counts[0]++
		if cur == nil || cur.id != svcID {
			if err := flush(false); err != nil {
				return counts, err
			}
			cur = &huntService{id: svcID, address: address, port: port, protocol: protocol}
			if covering != nil {
				cur.covered = *covering
			}
		}
		cur.observed = runID
		if sig.Path != "/" {
			continue
		}
		h, err := inv.decodeHTTP(doc, headers, cookies)
		if err != nil {
			return counts, fmt.Errorf("observation of %s %d/%s in run %d: %w", address, port, protocol, runID, err)
		}
		var plain []byte
		if body != nil {
			if plain, err = inv.open(body); err != nil {
				return counts, fmt.Errorf("body of %s %d/%s in run %d: %w", address, port, protocol, runID, err)
			}
			if plain == nil {
				plain = []byte{}
			}
		}
		e, ok := sig.EvaluateHistory(h, plain)
		if !ok {
			continue
		}
		cur.evaluable = true
		if !e.Matched {
			continue
		}
		if !cur.matched {
			cur.matched, cur.first = true, runID
		}
		cur.last, cur.version, cur.evidence = runID, e.Version, sig.Evidence(e.Evidence)
	}
	if err := rows.Err(); err != nil {
		return counts, fmt.Errorf("query observations: %w", err)
	}
	return counts, flush(true)
}

func (inv *Inventory) runScopes(ctx context.Context, latest *int64) (map[int64]string, map[string]int64, error) {
	rows, err := inv.db.Pool.Query(ctx, `SELECT id, settings, scope FROM runs r WHERE id <= $1 AND `+startedRunSQL, latest)
	if err != nil {
		return nil, nil, fmt.Errorf("query run scopes: %w", err)
	}
	defer rows.Close()
	scopeOf, scopeLatest := map[int64]string{}, map[string]int64{}
	for rows.Next() {
		var (
			id            int64
			settings, enc []byte
			st            RunSettings
		)
		if err := rows.Scan(&id, &settings, &enc); err != nil {
			return nil, nil, fmt.Errorf("scan run scope: %w", err)
		}
		if err := inv.OpenSettings(settings, enc, &st); err != nil {
			return nil, nil, fmt.Errorf("run %d scope: %w", id, err)
		}
		key, err := json.Marshal([2][]string{st.Targets, st.Excludes})
		if err != nil {
			return nil, nil, fmt.Errorf("run %d scope: %w", id, err)
		}
		scope := string(key)
		scopeOf[id], scopeLatest[scope] = scope, max(scopeLatest[scope], id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("query run scopes: %w", err)
	}
	return scopeOf, scopeLatest, nil
}

func (inv *Inventory) writeHuntResults(ctx context.Context, huntID int64, batch []huntService) error {
	data := make([][]any, len(batch))
	for i, s := range batch {
		var first, last *int64
		var evidence []byte
		if s.matched {
			first, last = &s.first, &s.last
			var err error
			if evidence, err = inv.sealString(s.evidence); err != nil {
				return err
			}
		}
		data[i] = []any{huntID, s.id, s.address, s.port, s.protocol, s.evaluable, first, last, s.inLatest, s.version, evidence}
	}
	if _, err := inv.db.Pool.CopyFrom(ctx, pgx.Identifier{"hunt_results"},
		[]string{"hunt_id", "service_id", "address", "port", "protocol", "evaluable", "first_run_id", "last_run_id", "in_latest", "version", "evidence"},
		pgx.CopyFromRows(data)); err != nil {
		return fmt.Errorf("write hunt results: %w", err)
	}
	return nil
}

func (inv *Inventory) GetHunt(ctx context.Context, id int64) (Hunt, error) {
	var (
		h      Hunt
		ns     int64
		lr     *string
		source []byte
	)
	err := inv.db.Pool.QueryRow(ctx, `SELECT hu.id, hu.signature_id, hu.source, hu.actor, hu.since, hu.latest_run_id, r.name,
			hu.observations, hu.matched, hu.in_latest, hu.not_evaluable, hu.duration_ns, hu.created_at
		FROM hunts hu LEFT JOIN runs r ON r.id = hu.latest_run_id WHERE hu.id = $1`, id).Scan(
		&h.ID, &h.SignatureID, &source, &h.Actor, &h.Since, &h.latestRunID, &lr,
		&h.Observations, &h.Matched, &h.InLatest, &h.NotEvaluable, &ns, &h.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Hunt{}, fmt.Errorf("%w: %d", ErrUnknownHunt, id)
	}
	if err != nil {
		return Hunt{}, fmt.Errorf("get hunt %d: %w", id, err)
	}
	if h.Source, err = inv.openString(source); err != nil {
		return Hunt{}, fmt.Errorf("hunt %d source: %w", id, err)
	}
	if lr != nil {
		h.LatestRun = *lr
	}
	h.Duration = time.Duration(ns)
	return h, nil
}

func (inv *Inventory) HuntResults(ctx context.Context, id int64, offset, limit int, fn func(HuntResult) error) error {
	q := `SELECT r.address, r.port, r.protocol, r.evaluable, COALESCE(fr.name, ''), COALESCE(lr.name, ''), r.in_latest, r.version
		FROM hunt_results r
		LEFT JOIN runs fr ON fr.id = r.first_run_id
		LEFT JOIN runs lr ON lr.id = r.last_run_id
		WHERE r.hunt_id = $1
		ORDER BY r.evaluable DESC, r.in_latest DESC, r.address::inet, r.port, r.protocol
		OFFSET $2`
	args := []any{id, max(offset, 0)}
	if limit > 0 {
		q += ` LIMIT $3`
		args = append(args, limit)
	}
	rows, err := inv.db.Pool.Query(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("results of hunt %d: %w", id, err)
	}
	defer rows.Close()
	for rows.Next() {
		var r HuntResult
		if err := rows.Scan(&r.Address, &r.Port, &r.Protocol, &r.Evaluable, &r.FirstRun, &r.LastRun, &r.InLatest, &r.Version); err != nil {
			return fmt.Errorf("scan result of hunt %d: %w", id, err)
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("results of hunt %d: %w", id, err)
	}
	return nil
}

func (inv *Inventory) RecordHuntFindings(ctx context.Context, id int64, actor, addr string) (int, error) {
	h, err := inv.GetHunt(ctx, id)
	if err != nil {
		return 0, err
	}
	sig, err := detect.ParseOne([]byte(h.Source))
	if err != nil {
		return 0, fmt.Errorf("signature of hunt %d: %w", id, err)
	}
	var n int64
	err = inv.db.Tx(ctx, func(tx pgx.Tx) error {
		var latest *int64
		if err := tx.QueryRow(ctx, `SELECT max(id) FROM runs`).Scan(&latest); err != nil {
			return fmt.Errorf("latest run: %w", err)
		}
		if h.latestRunID == nil || latest == nil || *latest != *h.latestRunID {
			return ErrStaleHunt
		}
		tag, err := tx.Exec(ctx, `INSERT INTO findings
				(service_observation_id, ordinal, signature_id, kind, name, version, confidence, evidence, source)
			SELECT so.id, COALESCE((SELECT max(f.ordinal) + 1 FROM findings f WHERE f.service_observation_id = so.id), 0),
				$2, $3, $4, r.version, $5, r.evidence, $6
			FROM hunt_results r
			JOIN service_observations so ON so.service_id = r.service_id AND so.run_id = r.last_run_id
			WHERE r.hunt_id = $1 AND r.in_latest AND r.evaluable
				AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.service_observation_id = so.id AND f.signature_id = $2)`,
			id, sig.ID, sig.Kind, sig.Name, sig.Confidence, SourceRetroHunt)
		if err != nil {
			return fmt.Errorf("insert findings: %w", err)
		}
		n = tag.RowsAffected()
		if _, err := tx.Exec(ctx, `INSERT INTO audit_log (actor, action, target, address) VALUES ($1, $2, $3, $4)`,
			actor, AuditHuntRecord, sig.ID, addr); err != nil {
			return fmt.Errorf("write audit %s: %w", AuditHuntRecord, err)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("record findings of hunt %d: %w", id, err)
	}
	return int(n), nil
}

func ParseSince(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if n, ok := strings.CutSuffix(s, "d"); ok && err != nil {
		days, derr := strconv.Atoi(n)
		d, err = time.Duration(days)*24*time.Hour, derr
	}
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%q is not a positive duration such as 72h or 30d", s)
	}
	return d, nil
}
