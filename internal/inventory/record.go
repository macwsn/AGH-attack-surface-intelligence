package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (inv *Inventory) CreateRun(ctx context.Context, spec RunSpec) (Run, error) {
	if strings.TrimSpace(spec.Name) == "" {
		return Run{}, errors.New("inventory: run name is required")
	}
	n := spec.InactiveAfter
	if n <= 0 {
		n = DefaultInactiveAfter
	}
	settings, err := json.Marshal(spec.Settings)
	if err != nil {
		return Run{}, fmt.Errorf("encode settings of run %q: %w", spec.Name, err)
	}
	r, err := scanRun(inv.db.Pool.QueryRow(ctx,
		`INSERT INTO runs (name, inactive_after, status, settings) VALUES ($1, $2, $3, $4) RETURNING `+runColumns,
		spec.Name, n, RunRunning, string(settings)))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return Run{}, fmt.Errorf("%w: %q", ErrRunExists, spec.Name)
	}
	if err != nil {
		return Run{}, fmt.Errorf("create run %q: %w", spec.Name, err)
	}
	return r, nil
}

type preparedHost struct {
	address   string
	hostnames []string
	services  []preparedService
}

type preparedService struct {
	ServiceResult
	http     []byte
	headers  []byte
	cookies  []byte
	evidence [][]byte
}

func (inv *Inventory) prepareGroup(g GroupResult) ([]string, []preparedHost, error) {
	if g.Index < 0 {
		return nil, nil, fmt.Errorf("inventory: negative group index %d", g.Index)
	}
	if g.Duration < 0 {
		return nil, nil, fmt.Errorf("inventory: negative duration %s of group %d", g.Duration, g.Index)
	}
	covered := map[string]bool{}
	var addresses []string
	cover := func(a string) {
		if !covered[a] {
			covered[a] = true
			addresses = append(addresses, a)
		}
	}
	for _, a := range g.Addresses {
		addr, err := normalizeAddress(a)
		if err != nil {
			return nil, nil, err
		}
		cover(addr)
	}

	seenHost := map[string]bool{}
	hosts := make([]preparedHost, 0, len(g.Hosts))
	for _, h := range g.Hosts {
		addr, err := normalizeAddress(h.Address)
		if err != nil {
			return nil, nil, err
		}
		if seenHost[addr] {
			return nil, nil, fmt.Errorf("inventory: host %s listed twice in group %d", addr, g.Index)
		}
		seenHost[addr] = true
		cover(addr)
		ph := preparedHost{address: addr, hostnames: sortedUnique(h.Hostnames)}
		seenSvc := map[string]bool{}
		for _, s := range h.Services {
			s.Protocol = strings.ToLower(strings.TrimSpace(s.Protocol))
			if s.Protocol == "" {
				s.Protocol = "tcp"
			}
			if s.Port < 0 || s.Port > 65535 {
				return nil, nil, fmt.Errorf("inventory: host %s: invalid port %d", addr, s.Port)
			}
			key := fmt.Sprintf("%d/%s", s.Port, s.Protocol)
			if seenSvc[key] {
				return nil, nil, fmt.Errorf("inventory: host %s: service %s listed twice", addr, key)
			}
			seenSvc[key] = true
			ps, err := inv.prepareService(s)
			if err != nil {
				return nil, nil, fmt.Errorf("inventory: host %s service %s: %w", addr, key, err)
			}
			ph.services = append(ph.services, ps)
		}
		hosts = append(hosts, ph)
	}
	return addresses, hosts, nil
}

func (inv *Inventory) prepareService(s ServiceResult) (preparedService, error) {
	ps := preparedService{ServiceResult: s}
	if s.HTTP != nil {
		plain := *s.HTTP
		plain.Headers = nil
		plain.Cookies = nil
		doc, err := json.Marshal(plain)
		if err != nil {
			return ps, fmt.Errorf("encode http: %w", err)
		}
		ps.http = doc
		headers := s.HTTP.Headers
		if headers == nil {
			headers = map[string]string{}
		}
		if ps.headers, err = inv.sealJSON(headers); err != nil {
			return ps, err
		}
		if ps.cookies, err = inv.sealJSON(nonNil(s.HTTP.Cookies)); err != nil {
			return ps, err
		}
	}
	for _, f := range s.Findings {
		ev, err := inv.sealString(f.Evidence)
		if err != nil {
			return ps, err
		}
		ps.evidence = append(ps.evidence, ev)
	}
	return ps, nil
}

func (inv *Inventory) RecordGroup(ctx context.Context, runID int64, g GroupResult) error {
	addresses, hosts, err := inv.prepareGroup(g)
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
		if _, err := tx.Exec(ctx, `DELETE FROM run_groups WHERE run_id = $1 AND group_index = $2`, runID, g.Index); err != nil {
			return fmt.Errorf("replace previous recording: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO run_groups (run_id, group_index, address_count, hosts_found, duration_ns)
			VALUES ($1, $2, $3, $4, $5)`, runID, g.Index, len(addresses), len(hosts), g.Duration.Nanoseconds()); err != nil {
			return fmt.Errorf("insert group: %w", err)
		}
		if len(addresses) > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO run_group_addresses (run_id, group_index, address)
				SELECT $1, $2, unnest($3::text[])`, runID, g.Index, addresses); err != nil {
				return fmt.Errorf("insert group coverage: %w", err)
			}
		}
		for _, h := range hosts {
			if err := recordHost(ctx, tx, runID, g.Index, h); err != nil {
				return fmt.Errorf("host %s: %w", h.address, err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("record group %d of run %d: %w", g.Index, runID, err)
	}
	return nil
}

func recordHost(ctx context.Context, tx pgx.Tx, runID int64, group int, h preparedHost) error {
	var hostID int64
	err := tx.QueryRow(ctx, `WITH ins AS (
			INSERT INTO hosts (address) VALUES ($1) ON CONFLICT (address) DO NOTHING RETURNING id)
		SELECT id FROM ins UNION ALL SELECT id FROM hosts WHERE address = $1 LIMIT 1`, h.address).Scan(&hostID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT id FROM hosts WHERE address = $1`, h.address).Scan(&hostID)
	}
	if err != nil {
		return fmt.Errorf("upsert host: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO host_observations (run_id, group_index, host_id, hostnames)
		VALUES ($1, $2, $3, $4)`, runID, group, hostID, h.hostnames); err != nil {
		return fmt.Errorf("insert host observation: %w", err)
	}
	for _, s := range h.services {
		if err := recordService(ctx, tx, runID, group, hostID, s); err != nil {
			return fmt.Errorf("service %d/%s: %w", s.Port, s.Protocol, err)
		}
	}
	return nil
}

func recordService(ctx context.Context, tx pgx.Tx, runID int64, group int, hostID int64, s preparedService) error {
	var svcID int64
	err := tx.QueryRow(ctx, `WITH ins AS (
			INSERT INTO services (host_id, port, protocol) VALUES ($1, $2, $3)
			ON CONFLICT (host_id, port, protocol) DO NOTHING RETURNING id)
		SELECT id FROM ins UNION ALL SELECT id FROM services WHERE host_id = $1 AND port = $2 AND protocol = $3 LIMIT 1`,
		hostID, s.Port, s.Protocol).Scan(&svcID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT id FROM services WHERE host_id = $1 AND port = $2 AND protocol = $3`,
			hostID, s.Port, s.Protocol).Scan(&svcID)
	}
	if err != nil {
		return fmt.Errorf("upsert service: %w", err)
	}
	var obsID int64
	if err := tx.QueryRow(ctx, `INSERT INTO service_observations
			(run_id, group_index, service_id, state, service, product, version, http, http_headers, http_cookies)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		runID, group, svcID, s.State, s.Service, s.Product, s.Version, jsonArg(s.http), s.headers, s.cookies).Scan(&obsID); err != nil {
		return fmt.Errorf("insert service observation: %w", err)
	}
	for i, t := range s.Technologies {
		if _, err := tx.Exec(ctx, `INSERT INTO technologies
				(service_observation_id, ordinal, name, category, version, confidence, source)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, obsID, i, t.Name, t.Category, t.Version, t.Confidence, t.Source); err != nil {
			return fmt.Errorf("insert technology %q: %w", t.Name, err)
		}
	}
	for i, f := range s.Findings {
		if _, err := tx.Exec(ctx, `INSERT INTO findings
				(service_observation_id, ordinal, signature_id, kind, name, version, confidence, evidence)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, obsID, i, f.SignatureID, f.Kind, f.Name, f.Version, f.Confidence, s.evidence[i]); err != nil {
			return fmt.Errorf("insert finding %q: %w", f.SignatureID, err)
		}
	}
	return nil
}

func jsonArg(doc []byte) any {
	if doc == nil {
		return nil
	}
	return string(doc)
}

func sortedUnique(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
