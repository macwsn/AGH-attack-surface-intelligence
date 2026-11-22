package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
)

const (
	TimingWindow = 10
	SlowFactor   = 3
	SlowMinMS    = 500
)

type ServiceTiming struct {
	Port     int
	Protocol string
	Service  string
	Error    string
	LatestMS int64
	MedianMS int64
	Runs     int
	Slower   bool
}

func Median(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	v := slices.Clone(values)
	slices.Sort(v)
	n := len(v)
	if n%2 == 1 {
		return v[n/2]
	}
	return (v[n/2-1] + v[n/2]) / 2
}

func SlowerThanUsual(latest, median int64) bool {
	return latest > SlowMinMS && latest > SlowFactor*median
}

func (inv *Inventory) ResponseTimes(ctx context.Context, address string) ([]ServiceTiming, error) {
	addr, err := normalizeAddress(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnknownHost, err)
	}
	var hostID int64
	err = inv.db.Pool.QueryRow(ctx, `SELECT id FROM hosts WHERE address = $1`, addr).Scan(&hostID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownHost, addr)
	}
	if err != nil {
		return nil, fmt.Errorf("look up host %s: %w", addr, err)
	}
	rows, err := inv.db.Pool.Query(ctx, `SELECT s.port, s.protocol, t.service, COALESCE(t.http->>'error', ''),
			(t.http->>'response_time_ms')::bigint
		FROM services s
		JOIN LATERAL (SELECT so.run_id, so.service, so.http FROM service_observations so
		              WHERE so.service_id = s.id AND so.http ? 'response_time_ms'
		              ORDER BY so.run_id DESC LIMIT $2) t ON true
		WHERE s.host_id = $1
		ORDER BY s.port, s.protocol, t.run_id DESC`, hostID, TimingWindow)
	if err != nil {
		return nil, fmt.Errorf("query response times of %s: %w", addr, err)
	}
	defer rows.Close()
	out := []ServiceTiming{}
	var window []int64
	finish := func() {
		if n := len(out); n > 0 {
			out[n-1].Runs = len(window)
			out[n-1].MedianMS = Median(window)
			out[n-1].Slower = SlowerThanUsual(out[n-1].LatestMS, out[n-1].MedianMS)
		}
	}
	for rows.Next() {
		var st ServiceTiming
		if err := rows.Scan(&st.Port, &st.Protocol, &st.Service, &st.Error, &st.LatestMS); err != nil {
			return nil, fmt.Errorf("scan response time: %w", err)
		}
		if n := len(out); n > 0 && out[n-1].Port == st.Port && out[n-1].Protocol == st.Protocol {
			window = append(window, st.LatestMS)
			continue
		}
		finish()
		out = append(out, st)
		window = []int64{st.LatestMS}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query response times of %s: %w", addr, err)
	}
	finish()
	return out, nil
}
