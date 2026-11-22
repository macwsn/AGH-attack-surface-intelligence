package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/probe"
)

var (
	ErrUnknownRun  = errors.New("inventory: unknown run")
	ErrRunExists   = errors.New("inventory: run already exists")
	ErrUnknownHost = errors.New("inventory: unknown host")
	ErrNoKeyring   = errors.New("inventory: no field encryption keyring")
)

func normalizeAddress(s string) (string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("inventory: invalid address %q: %w", s, err)
	}
	return a.Unmap().String(), nil
}

func (inv *Inventory) sealJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode sensitive field: %w", err)
	}
	return inv.seal(b)
}

func (inv *Inventory) sealString(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return inv.seal([]byte(s))
}

func (inv *Inventory) seal(b []byte) ([]byte, error) {
	if inv.keys == nil {
		return nil, ErrNoKeyring
	}
	out, err := inv.keys.Encrypt(b)
	if err != nil {
		return nil, fmt.Errorf("encrypt sensitive field: %w", err)
	}
	return out, nil
}

func (inv *Inventory) open(b []byte) ([]byte, error) {
	if b == nil {
		return nil, nil
	}
	if inv.keys == nil {
		return nil, ErrNoKeyring
	}
	out, err := inv.keys.Decrypt(b)
	if err != nil {
		return nil, fmt.Errorf("decrypt sensitive field: %w", err)
	}
	return out, nil
}

func (inv *Inventory) openString(b []byte) (string, error) {
	out, err := inv.open(b)
	return string(out), err
}

func (inv *Inventory) openJSON(b []byte, v any) error {
	out, err := inv.open(b)
	if err != nil || out == nil {
		return err
	}
	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("decode sensitive field: %w", err)
	}
	return nil
}

const runColumns = `id, name, inactive_after, started_at, finished_at, status, settings, scope, COALESCE(address_total, 0), source, packets, inflight_addresses, ` + stalledColumn

const stalledColumn = `(status = 'running' AND COALESCE(heartbeat_at, started_at) < now() - interval '60 seconds')`

func (inv *Inventory) scanRun(row pgx.Row) (Run, error) {
	var (
		r               Run
		settings, scope []byte
	)
	if err := row.Scan(&r.ID, &r.Name, &r.InactiveAfter, &r.StartedAt, &r.FinishedAt, &r.Status, &settings, &scope, &r.AddressTotal, &r.Source, &r.Packets, &r.InFlight, &r.Stalled); err != nil {
		return Run{}, err
	}
	if err := inv.OpenSettings(settings, scope, &r.Settings); err != nil {
		return Run{}, fmt.Errorf("decode settings of run %q: %w", r.Name, err)
	}
	return r, nil
}

type runScope struct {
	Targets  []string `json:"targets"`
	Excludes []string `json:"excludes"`
}

func (inv *Inventory) SealSettings(st RunSettings) (string, []byte, error) {
	scope, err := inv.sealJSON(runScope{Targets: st.Targets, Excludes: st.Excludes})
	if err != nil {
		return "", nil, err
	}
	st.Targets, st.Excludes = nil, nil
	settings, err := json.Marshal(st)
	if err != nil {
		return "", nil, fmt.Errorf("encode settings: %w", err)
	}
	return string(settings), scope, nil
}

func (inv *Inventory) OpenSettings(settings, scope []byte, st *RunSettings) error {
	if err := json.Unmarshal(settings, st); err != nil {
		return err
	}
	if scope == nil {
		return nil
	}
	var sc runScope
	if err := inv.openJSON(scope, &sc); err != nil {
		return err
	}
	st.Targets, st.Excludes = sc.Targets, sc.Excludes
	return nil
}

func (inv *Inventory) runByName(ctx context.Context, tx pgx.Tx, name string) (Run, bool, error) {
	q := `SELECT ` + runColumns + ` FROM runs WHERE name = $1`
	args := []any{name}
	if name == "" {
		q = `SELECT ` + runColumns + ` FROM runs ORDER BY id DESC LIMIT 1`
		args = nil
	}
	r, err := inv.scanRun(tx.QueryRow(ctx, q, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		if name == "" {
			return Run{}, false, nil
		}
		return Run{}, false, fmt.Errorf("%w: %q", ErrUnknownRun, name)
	}
	if err != nil {
		return Run{}, false, fmt.Errorf("look up run %q: %w", name, err)
	}
	return r, true, nil
}

func (inv *Inventory) state(ctx context.Context, asOfRun string) (Run, []ExportHost, error) {
	var (
		run   Run
		hosts []ExportHost
	)
	err := pgx.BeginTxFunc(ctx, inv.db.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		r, ok, err := inv.runByName(ctx, tx, asOfRun)
		if err != nil || !ok {
			return err
		}
		run = r
		hosts, err = inv.loadHosts(ctx, tx, r, nil)
		return err
	})
	if err != nil {
		return Run{}, nil, fmt.Errorf("read inventory as of run %q: %w", asOfRun, err)
	}
	if hosts == nil {
		hosts = []ExportHost{}
	}
	return run, hosts, nil
}

const hostsAsOfSQL = `
SELECT h.id, h.address, h.tags, h.notes, h.display_name, h.owner, h.criticality, h.status_override,
       fr.started_at, lr.started_at, lo.hostnames, COALESCE(sn.seen, '{}'), COALESCE(sn.runs, '{}'),
       COALESCE(sn.at, '{}'), COALESCE(sn.external, '{}'),
       EXISTS (SELECT 1 FROM run_group_addresses c JOIN runs r ON r.id = c.run_id
               WHERE c.address = h.address AND c.run_id <= $1 AND r.source = 'scan')
FROM hosts h
JOIN LATERAL (SELECT min(run_id) AS first, max(run_id) AS last
              FROM host_observations WHERE host_id = h.id AND run_id <= $1) o ON o.first IS NOT NULL
JOIN runs fr ON fr.id = o.first
JOIN runs lr ON lr.id = o.last
JOIN host_observations lo ON lo.host_id = h.id AND lo.run_id = o.last
JOIN LATERAL (SELECT array_agg(ho.run_id IS NOT NULL ORDER BY c.run_id) AS seen,
                     array_agg(c.run_id ORDER BY c.run_id) AS runs,
                     array_agg(g.completed_at ORDER BY c.run_id) AS at,
                     array_agg(cr.source <> 'scan' ORDER BY c.run_id) AS external
              FROM run_group_addresses c
              JOIN run_groups g ON g.run_id = c.run_id AND g.group_index = c.group_index
              JOIN runs cr ON cr.id = c.run_id
              LEFT JOIN host_observations ho ON ho.host_id = h.id AND ho.run_id = c.run_id
              WHERE c.address = h.address AND c.run_id BETWEEN o.first AND $1) sn ON true
WHERE ($2::text = '' OR h.address = $2)`

const servicesAsOfSQL = `
SELECT s.id, s.host_id, s.port, s.protocol, fr.started_at, lr.started_at, COALESCE(sn.seen, '{}'), COALESCE(sn.runs, '{}'),
       lo.id, lo.state, lo.service, lo.product, lo.version, lo.http, lo.http_headers, lo.http_cookies, lo.field_state
FROM services s
JOIN hosts h ON h.id = s.host_id
JOIN LATERAL (SELECT min(run_id) AS first, max(run_id) AS last
              FROM service_observations WHERE service_id = s.id AND run_id <= $1) o ON o.first IS NOT NULL
JOIN runs fr ON fr.id = o.first
JOIN runs lr ON lr.id = o.last
JOIN service_observations lo ON lo.service_id = s.id AND lo.run_id = o.last
JOIN LATERAL (SELECT array_agg(so.id IS NOT NULL ORDER BY c.run_id) AS seen,
                     array_agg(c.run_id ORDER BY c.run_id) AS runs
              FROM run_group_addresses c
              JOIN runs cr ON cr.id = c.run_id
              LEFT JOIN service_observations so ON so.service_id = s.id AND so.run_id = c.run_id
              WHERE c.address = h.address AND c.run_id BETWEEN o.first AND $1
                AND (so.id IS NOT NULL OR (s.protocol = 'tcp' AND s.port = ANY (c.ports))
                     OR (c.ports IS NULL AND (cr.ports IS NULL OR s.protocol <> 'tcp' OR s.port = ANY (cr.ports))))) sn ON true
WHERE ($2::text = '' OR h.address = $2)`

func seenIn(seen []bool, runIDs []int64, runID int64) bool {
	n := len(runIDs)
	return n > 0 && n == len(seen) && runIDs[n-1] == runID && seen[n-1]
}

func (inv *Inventory) loadHosts(ctx context.Context, tx pgx.Tx, run Run, hostIDs []int64) ([]ExportHost, error) {
	return inv.loadHostsWhere(ctx, tx, run, "", hostIDs)
}

func (inv *Inventory) loadHostsAt(ctx context.Context, tx pgx.Tx, run Run, address string) ([]ExportHost, error) {
	return inv.loadHostsWhere(ctx, tx, run, address, nil)
}

func (inv *Inventory) loadHostsWhere(ctx context.Context, tx pgx.Tx, run Run, address string, hostIDs []int64) ([]ExportHost, error) {
	zones, err := runZones(ctx, tx, run.ID)
	if err != nil {
		return nil, err
	}
	q, args := hostsAsOfSQL, []any{run.ID, address}
	if hostIDs != nil {
		q, args = q+` AND h.id = ANY($3)`, append(args, hostIDs)
	}
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query hosts: %w", err)
	}
	var (
		hosts    []ExportHost
		byID     = map[int64]int{}
		ignored  = map[int64]map[int64]bool{}
		hostID   int64
		notes    []byte
		name     []byte
		owner    []byte
		seen     []bool
		runIDs   []int64
		at       []time.Time
		external []bool
	)
	for rows.Next() {
		var h ExportHost
		if err := rows.Scan(&hostID, &h.Address, &h.Tags, &notes, &name, &owner, &h.Criticality,
			&h.StatusOverride, &h.FirstSeen, &h.LastSeen, &h.Hostnames, &seen, &runIDs, &at, &external, &h.ScanCovered); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan host: %w", err)
		}
		if h.Notes, h.DisplayName, h.Owner, err = inv.openUserFields(notes, name, owner); err != nil {
			rows.Close()
			return nil, fmt.Errorf("host %s: %w", h.Address, err)
		}
		cov := make([]coverage, len(seen))
		for i := range seen {
			cov[i] = coverage{run: runIDs[i], hour: at[i].In(zones.of(runIDs[i])).Hour(), seen: seen[i], external: external[i]}
		}
		if len(at) > 0 {
			h.LastCovered = at[len(at)-1]
		}
		h.NotInRun = !seenIn(seen, runIDs, run.ID)
		rh := applyRhythm(cov, run.ID)
		h.Status, h.MissedRuns, h.Stability = DeriveStatus(rh.seen, run.InactiveAfter)
		if h.Availability = rh.profile.Export(); h.Availability != nil {
			h.Availability.Expected = rh.expected
		}
		if len(rh.ignored) > 0 {
			ignored[hostID] = rh.ignored
		}
		h.Tags = nonNil(h.Tags)
		h.Hostnames = nonNil(h.Hostnames)
		h.Services = []ExportService{}
		byID[hostID] = len(hosts)
		hosts = append(hosts, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query hosts: %w", err)
	}

	svcs, owners, obsIDs, err := inv.loadServices(ctx, tx, run, address, hostIDs, ignored)
	if err != nil {
		return nil, err
	}
	techs, findings, err := inv.loadDetections(ctx, tx, obsIDs)
	if err != nil {
		return nil, err
	}
	for i := range svcs {
		idx, ok := byID[owners[i]]
		if !ok {
			continue
		}
		svcs[i].Technologies = nonNil(techs[obsIDs[i]])
		svcs[i].Findings = nonNil(findings[obsIDs[i]])
		hosts[idx].Services = append(hosts[idx].Services, svcs[i])
	}

	for i := range hosts {
		sort.Slice(hosts[i].Services, func(a, b int) bool {
			sa, sb := hosts[i].Services[a], hosts[i].Services[b]
			if sa.Port != sb.Port {
				return sa.Port < sb.Port
			}
			return sa.Protocol < sb.Protocol
		})
		hosts[i].InterestScore, _ = Score(hosts[i], run.StartedAt, inv.Interest)
	}
	sort.Slice(hosts, func(a, b int) bool { return addressLess(hosts[a].Address, hosts[b].Address) })
	return hosts, nil
}

func (inv *Inventory) loadServices(ctx context.Context, tx pgx.Tx, run Run, address string, hostIDs []int64, ignored map[int64]map[int64]bool) ([]ExportService, []int64, []int64, error) {
	q, args := servicesAsOfSQL, []any{run.ID, address}
	if hostIDs != nil {
		q, args = q+` AND s.host_id = ANY($3)`, append(args, hostIDs)
	}
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("query services: %w", err)
	}
	defer rows.Close()
	var (
		svcs                []ExportService
		owners, obsIDs      []int64
		svcID, hostID, obID int64
		seen                []bool
		runIDs              []int64
		httpDoc             []byte
		headers, cookies    []byte
		fieldState          []byte
	)
	for rows.Next() {
		var s ExportService
		if err := rows.Scan(&svcID, &hostID, &s.Port, &s.Protocol, &s.FirstSeen, &s.LastSeen, &seen, &runIDs,
			&obID, &s.State, &s.Service, &s.Product, &s.Version, &httpDoc, &headers, &cookies, &fieldState); err != nil {
			return nil, nil, nil, fmt.Errorf("scan service: %w", err)
		}
		s.NotInRun = !seenIn(seen, runIDs, run.ID)
		if skip := ignored[hostID]; len(skip) > 0 {
			kept := seen[:0]
			for i, v := range seen {
				if !skip[runIDs[i]] {
					kept = append(kept, v)
				}
			}
			seen = kept
		}
		s.Status, s.MissedRuns, s.Stability = DeriveStatus(seen, run.InactiveAfter)
		if s.HTTP, err = inv.decodeHTTP(httpDoc, headers, cookies); err != nil {
			return nil, nil, nil, fmt.Errorf("service %d/%s: %w", s.Port, s.Protocol, err)
		}
		var st FieldState
		if err := inv.openJSON(fieldState, &st); err != nil {
			return nil, nil, nil, fmt.Errorf("service %d/%s field state: %w", s.Port, s.Protocol, err)
		}
		s.Volatile = st.Volatile()
		svcs = append(svcs, s)
		owners = append(owners, hostID)
		obsIDs = append(obsIDs, obID)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("query services: %w", err)
	}
	return svcs, owners, obsIDs, nil
}

type zoneMap map[int64]*time.Location

func (z zoneMap) of(runID int64) *time.Location {
	if loc, ok := z[runID]; ok {
		return loc
	}
	return time.UTC
}

func runZones(ctx context.Context, tx pgx.Tx, asOf int64) (zoneMap, error) {
	rows, err := tx.Query(ctx, `SELECT id, schedule->>'timezone' FROM runs
		WHERE id <= $1 AND COALESCE(schedule->>'timezone', '') <> ''`, asOf)
	if err != nil {
		return nil, fmt.Errorf("query run timezones: %w", err)
	}
	defer rows.Close()
	zones := zoneMap{}
	cache := map[string]*time.Location{}
	var (
		id   int64
		name string
	)
	for rows.Next() {
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("scan run timezone: %w", err)
		}
		loc, ok := cache[name]
		if !ok {
			if loc, err = time.LoadLocation(name); err != nil {
				loc = time.UTC
			}
			cache[name] = loc
		}
		zones[id] = loc
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query run timezones: %w", err)
	}
	return zones, nil
}

func (inv *Inventory) decodeHTTP(doc, headers, cookies []byte) (*probe.HTTP, error) {
	if doc == nil {
		return nil, nil
	}
	var h probe.HTTP
	if err := json.Unmarshal(doc, &h); err != nil {
		return nil, fmt.Errorf("decode http: %w", err)
	}
	if err := inv.openJSON(headers, &h.Headers); err != nil {
		return nil, fmt.Errorf("http headers: %w", err)
	}
	if err := inv.openJSON(cookies, &h.Cookies); err != nil {
		return nil, fmt.Errorf("http cookies: %w", err)
	}
	if h.Headers == nil {
		h.Headers = map[string]string{}
	}
	h.Cookies = nonNil(h.Cookies)
	h.RedirectChain = nonNil(h.RedirectChain)
	return &h, nil
}

func (inv *Inventory) loadDetections(ctx context.Context, tx pgx.Tx, obsIDs []int64) (map[int64][]Technology, map[int64][]Finding, error) {
	techs := map[int64][]Technology{}
	findings := map[int64][]Finding{}
	if len(obsIDs) == 0 {
		return techs, findings, nil
	}
	rows, err := tx.Query(ctx, `SELECT service_observation_id, name, category, version, confidence, source
		FROM technologies WHERE service_observation_id = ANY($1) ORDER BY service_observation_id, ordinal`, obsIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("query technologies: %w", err)
	}
	var id int64
	for rows.Next() {
		var t Technology
		if err := rows.Scan(&id, &t.Name, &t.Category, &t.Version, &t.Confidence, &t.Source); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("scan technology: %w", err)
		}
		techs[id] = append(techs[id], t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("query technologies: %w", err)
	}

	rows, err = tx.Query(ctx, `SELECT service_observation_id, signature_id, kind, name, version, confidence, evidence, source
		FROM findings WHERE service_observation_id = ANY($1) ORDER BY service_observation_id, ordinal`, obsIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	var evidence []byte
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&id, &f.SignatureID, &f.Kind, &f.Name, &f.Version, &f.Confidence, &evidence, &f.Source); err != nil {
			return nil, nil, fmt.Errorf("scan finding: %w", err)
		}
		if f.Evidence, err = inv.openString(evidence); err != nil {
			return nil, nil, fmt.Errorf("finding %s evidence: %w", f.SignatureID, err)
		}
		findings[id] = append(findings[id], f)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("query findings: %w", err)
	}
	return techs, findings, nil
}

func addressLess(a, b string) bool {
	pa, errA := netip.ParseAddr(a)
	pb, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a < b
	}
	return pa.Less(pb)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
