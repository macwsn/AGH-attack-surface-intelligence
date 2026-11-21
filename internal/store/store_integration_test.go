//go:build integration

package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"asi/internal/store/storetest"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestMigrateIdempotent(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	all, err := Migrations()
	if err != nil || len(all) == 0 {
		t.Fatalf("Migrations() = %v, %v", all, err)
	}
	first, err := s.Migrate(ctx)
	if err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if len(first) != len(all) {
		t.Fatalf("first Migrate applied %v, want all %d", first, len(all))
	}
	second, err := s.Migrate(ctx)
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("second Migrate applied %v, want none", second)
	}

	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if n != len(all) {
		t.Fatalf("schema_migrations has %d rows, want %d", n, len(all))
	}
	var schema string
	if err := s.Pool.QueryRow(ctx, `SELECT table_schema FROM information_schema.tables WHERE table_name = 'settings' AND table_schema = current_schema()`).Scan(&schema); err != nil {
		t.Fatalf("settings table not in the test schema: %v", err)
	}
}

func TestMigrateFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	bad := []Migration{
		{Version: "0001_ok", SQL: `CREATE TABLE ok_table (id int)`},
		{Version: "0002_bad", SQL: `CREATE TABLE broken (`},
	}
	if _, err := s.migrate(ctx, bad); err == nil {
		t.Fatal("migrate with a broken migration succeeded")
	}
	var exists bool
	if err := s.Pool.QueryRow(ctx, `SELECT to_regclass('ok_table') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatalf("check ok_table: %v", err)
	}
	if exists {
		t.Fatal("ok_table survived a failed migration run")
	}
}

func TestTx(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if err := s.Tx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('committed', '\x01')`)
		return err
	}); err != nil {
		t.Fatalf("Tx commit: %v", err)
	}

	boom := errors.New("boom")
	err := s.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('rolled-back', '\x01')`); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Tx error = %v, want boom", err)
	}

	rows, err := s.Pool.Query(ctx, `SELECT key FROM settings ORDER BY key`)
	if err != nil {
		t.Fatalf("query settings: %v", err)
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("collect settings: %v", err)
	}
	if len(keys) != 1 || keys[0] != "committed" {
		t.Fatalf("settings keys = %v, want [committed]", keys)
	}
}

func TestEncryptedValueStoredAndRead(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	k := mustKeyring(t, key(3))
	ct, err := k.Encrypt([]byte("defectdojo-token"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('dojo', $1)`, ct); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var stored []byte
	if err := s.Pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = 'dojo'`).Scan(&stored); err != nil {
		t.Fatalf("select: %v", err)
	}
	plain, err := k.Decrypt(stored)
	if err != nil || string(plain) != "defectdojo-token" {
		t.Fatalf("Decrypt stored value = %q, %v", plain, err)
	}
}
