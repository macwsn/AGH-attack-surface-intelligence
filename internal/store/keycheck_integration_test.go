//go:build integration

package store

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestStartupKeyCheckIsBoundedOnLargeObservationsTable(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	k, err := NewKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := k.Encrypt(bytes.Repeat([]byte("h"), 1024))
	if err != nil {
		t.Fatal(err)
	}
	cookies, err := k.Encrypt(bytes.Repeat([]byte("c"), 256))
	if err != nil {
		t.Fatal(err)
	}
	body, err := k.Encrypt(bytes.Repeat([]byte("b"), 4096))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO runs (id, name, inactive_after) VALUES (1, 'large', 3)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO run_groups (run_id, group_index) VALUES (1, 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO hosts (address)
		SELECT '10.' || (i / 65536) || '.' || (i / 256 % 256) || '.' || (i % 256) FROM generate_series(1, 50000) i`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO services (host_id, port, protocol) SELECT id, 443, 'tcp' FROM hosts`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO service_observations (run_id, group_index, service_id, http_headers, http_cookies, http_body)
		SELECT 1, 0, id, $1, $2, $3 FROM services`, headers, cookies, body); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM service_observations`).Scan(&n); err != nil || n != 50000 {
		t.Fatalf("service_observations rows = %d, %v; want 50000", n, err)
	}
	if err := s.CheckKeys(ctx, k); err != nil {
		t.Fatalf("CheckKeys warm-up: %v", err)
	}
	start := time.Now()
	err = s.CheckKeys(ctx, k)
	took := time.Since(start)
	if err != nil {
		t.Fatalf("CheckKeys: %v", err)
	}
	if took >= 200*time.Millisecond {
		t.Fatalf("startup key check took %s with 50000 observation rows, want under 200ms (read key ids in use from a small table, not the data rows)", took)
	}
}
