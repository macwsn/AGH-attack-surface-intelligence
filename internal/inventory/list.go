package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	DefaultPerPage = 50
	MaxPerPage     = 200
	maxPage        = 1 << 30
)

var ErrInvalidQuery = errors.New("inventory: invalid host query")

type HostQuery struct {
	Status      string
	Port        int
	Service     string
	Technology  string
	FindingKind string
	Tag         string
	Text        string
	Sort        string
	Desc        bool
	Page        int
	PerPage     int
}

type HostRow struct {
	Address        string
	DisplayName    string
	Hostnames      []string
	Tags           []string
	Criticality    string
	StatusOverride string
	Status         Status
	MissedRuns     int
	Stability      float64
	InterestScore  int
	Ports          []int
	PortStatus     map[int]Status
	Services       []string
	Technologies   []string
	FindingKinds   []string
	Titles         []string
	FirstSeen      time.Time
	LastSeen       time.Time
}

type HostPage struct {
	Hosts   []HostRow
	Total   int
	Page    int
	PerPage int
}

var hostSortKeys = map[string]string{
	"address":      "s.address",
	"status":       "CASE s.status WHEN 'active' THEN 0 WHEN 'unstable' THEN 1 ELSE 2 END",
	"interest":     "s.interest_score",
	"last_seen":    "s.last_seen",
	"display_name": "COALESCE(dn.rank, 0)",
}

func likePattern(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(s) + "%"
}

func (inv *Inventory) ListHosts(ctx context.Context, q HostQuery) (HostPage, error) {
	sortKey := q.Sort
	if sortKey == "" {
		sortKey = "address"
	}
	orderExpr, ok := hostSortKeys[sortKey]
	if !ok {
		return HostPage{}, fmt.Errorf("%w: unknown sort key %q", ErrInvalidQuery, q.Sort)
	}
	if q.Port < 0 || q.Port > 65535 {
		return HostPage{}, fmt.Errorf("%w: invalid port %d", ErrInvalidQuery, q.Port)
	}

	var (
		where []string
		args  []any
	)
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if status := strings.TrimSpace(q.Status); status != "" {
		switch Status(status) {
		case StatusActive, StatusUnstable, StatusInactive:
		default:
			return HostPage{}, fmt.Errorf("%w: unknown status %q", ErrInvalidQuery, q.Status)
		}
		where = append(where, "s.status = "+arg(status))
	}
	if q.Port != 0 {
		where = append(where, "s.ports @> "+arg([]int32{int32(q.Port)})+"::integer[]")
	}
	contains := func(column, value string) {
		if v := strings.TrimSpace(value); v != "" {
			where = append(where, column+" @> "+arg([]string{v})+"::text[]")
		}
	}
	contains("s.services", q.Service)
	contains("s.technologies", q.Technology)
	contains("s.finding_kinds", q.FindingKind)
	contains("h.tags", q.Tag)
	text := strings.TrimSpace(q.Text)
	var names map[int64]string
	if text != "" || sortKey == "display_name" {
		var err error
		if names, err = inv.displayNames(ctx); err != nil {
			return HostPage{}, fmt.Errorf("list hosts: %w", err)
		}
	}
	if text != "" {
		p := arg(likePattern(text))
		var named []int64
		for id, n := range names {
			if strings.Contains(strings.ToLower(n), strings.ToLower(text)) {
				named = append(named, id)
			}
		}
		where = append(where, "(h.address ILIKE "+p+" OR h.id = ANY("+arg(named)+"::bigint[])"+
			" OR EXISTS (SELECT 1 FROM unnest(s.hostnames || s.titles) x WHERE x ILIKE "+p+"))")
	}

	from := ` FROM host_summary s JOIN hosts h ON h.id = s.host_id`
	if sortKey == "display_name" {
		ids, ranks := nameRanks(names)
		from += ` LEFT JOIN unnest(` + arg(ids) + `::bigint[], ` + arg(ranks) + `::integer[]) AS dn(host_id, rank) ON dn.host_id = h.id`
	}
	if len(where) > 0 {
		from += ` WHERE ` + strings.Join(where, ` AND `)
	}
	dir := " ASC"
	if q.Desc {
		dir = " DESC"
	}
	order := orderExpr + dir
	if sortKey != "address" {
		order += ", s.address ASC"
	}

	page := HostPage{Page: min(max(q.Page, 1), maxPage), PerPage: q.PerPage, Hosts: []HostRow{}}
	if page.PerPage <= 0 {
		page.PerPage = DefaultPerPage
	}
	page.PerPage = min(page.PerPage, MaxPerPage)
	countArgs := len(args)
	limit, offset := arg(page.PerPage), arg(int64(page.Page-1)*int64(page.PerPage))

	err := pgx.BeginTxFunc(ctx, inv.db.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*)`+from, args[:countArgs]...).Scan(&page.Total); err != nil {
			return fmt.Errorf("count hosts: %w", err)
		}
		rows, err := tx.Query(ctx, `SELECT h.address, h.display_name, h.tags, h.criticality, h.status_override,
				s.status, s.missed_runs, s.stability, s.interest_score, s.ports, s.services, s.technologies,
				s.finding_kinds, s.titles, s.hostnames, s.first_seen, s.last_seen, s.host_id, s.last_run_id`+from+
			` ORDER BY `+order+` LIMIT `+limit+` OFFSET `+offset, args...)
		if err != nil {
			return fmt.Errorf("query hosts: %w", err)
		}
		defer rows.Close()
		byRun := map[int64][]int64{}
		rowOf := map[int64]int{}
		for rows.Next() {
			var (
				r             HostRow
				ports         []int32
				hostID, runID int64
				name          []byte
			)
			if err := rows.Scan(&r.Address, &name, &r.Tags, &r.Criticality, &r.StatusOverride,
				&r.Status, &r.MissedRuns, &r.Stability, &r.InterestScore, &ports, &r.Services, &r.Technologies,
				&r.FindingKinds, &r.Titles, &r.Hostnames, &r.FirstSeen, &r.LastSeen, &hostID, &runID); err != nil {
				return fmt.Errorf("scan host: %w", err)
			}
			if r.DisplayName, err = inv.openString(name); err != nil {
				return fmt.Errorf("display name of host %s: %w", r.Address, err)
			}
			r.Ports = make([]int, len(ports))
			for i, p := range ports {
				r.Ports[i] = int(p)
			}
			r.Tags, r.Services, r.Technologies = nonNil(r.Tags), nonNil(r.Services), nonNil(r.Technologies)
			r.FindingKinds, r.Titles, r.Hostnames = nonNil(r.FindingKinds), nonNil(r.Titles), nonNil(r.Hostnames)
			byRun[runID] = append(byRun[runID], hostID)
			rowOf[hostID] = len(page.Hosts)
			page.Hosts = append(page.Hosts, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		return inv.addPortStatus(ctx, tx, page.Hosts, byRun, rowOf)
	})
	if err != nil {
		return HostPage{}, fmt.Errorf("list hosts: %w", err)
	}
	return page, nil
}

func (inv *Inventory) displayNames(ctx context.Context) (map[int64]string, error) {
	rows, err := inv.db.Pool.Query(ctx, `SELECT id, display_name FROM hosts WHERE display_name IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("read display names: %w", err)
	}
	defer rows.Close()
	names := map[int64]string{}
	for rows.Next() {
		var (
			id     int64
			sealed []byte
		)
		if err := rows.Scan(&id, &sealed); err != nil {
			return nil, fmt.Errorf("read display names: %w", err)
		}
		n, err := inv.openString(sealed)
		if err != nil {
			return nil, fmt.Errorf("display name of host %d: %w", id, err)
		}
		names[id] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read display names: %w", err)
	}
	return names, nil
}

func nameRanks(names map[int64]string) ([]int64, []int32) {
	distinct := []string{""}
	for _, n := range names {
		distinct = append(distinct, n)
	}
	slices.Sort(distinct)
	distinct = slices.Compact(distinct)
	ids, ranks := make([]int64, 0, len(names)), make([]int32, 0, len(names))
	for id, n := range names {
		r, _ := slices.BinarySearch(distinct, n)
		ids, ranks = append(ids, id), append(ranks, int32(r))
	}
	return ids, ranks
}

var portRank = map[Status]int{StatusInactive: 0, StatusUnstable: 1, StatusActive: 2}

func (inv *Inventory) addPortStatus(ctx context.Context, tx pgx.Tx, hosts []HostRow, byRun map[int64][]int64, rowOf map[int64]int) error {
	for runID, ids := range byRun {
		run, err := inv.scanRun(tx.QueryRow(ctx, `SELECT `+runColumns+` FROM runs WHERE id = $1`, runID))
		if err != nil {
			return fmt.Errorf("look up run %d: %w", runID, err)
		}
		loaded, err := inv.loadHosts(ctx, tx, run, ids)
		if err != nil {
			return fmt.Errorf("load port status as of run %q: %w", run.Name, err)
		}
		byAddr := map[string]ExportHost{}
		for _, h := range loaded {
			byAddr[h.Address] = h
		}
		for _, id := range ids {
			r := &hosts[rowOf[id]]
			h, ok := byAddr[r.Address]
			if !ok {
				continue
			}
			r.PortStatus = map[int]Status{}
			for _, s := range h.Services {
				if s.Status == StatusInactive && !s.LastSeen.Equal(h.LastSeen) {
					continue
				}
				if cur, seen := r.PortStatus[s.Port]; !seen || portRank[s.Status] > portRank[cur] {
					r.PortStatus[s.Port] = s.Status
				}
			}
		}
	}
	return nil
}
