package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Migration struct {
	Version string
	SQL     string
}

func Migrations() ([]Migration, error) {
	return loadMigrations(migrationFiles, "migrations")
}

func loadMigrations(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		out = append(out, Migration{Version: strings.TrimSuffix(e.Name(), ".sql"), SQL: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func (s *Store) Migrate(ctx context.Context) ([]string, error) {
	migrations, err := Migrations()
	if err != nil {
		return nil, err
	}
	return s.migrate(ctx, migrations)
}

func (s *Store) migrate(ctx context.Context, migrations []Migration) ([]string, error) {
	var applied []string
	err := s.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('asi.migrate.' || current_schema()))`); err != nil {
			return fmt.Errorf("lock migrations: %w", err)
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
			return fmt.Errorf("create schema_migrations: %w", err)
		}
		rows, err := tx.Query(ctx, `SELECT version FROM schema_migrations`)
		if err != nil {
			return fmt.Errorf("list applied migrations: %w", err)
		}
		done, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("list applied migrations: %w", err)
		}
		seen := make(map[string]bool, len(done))
		for _, v := range done {
			seen[v] = true
		}
		for _, m := range migrations {
			if seen[m.Version] {
				continue
			}
			if _, err := tx.Exec(ctx, m.SQL); err != nil {
				return fmt.Errorf("apply migration %s: %w", m.Version, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, m.Version); err != nil {
				return fmt.Errorf("record migration %s: %w", m.Version, err)
			}
			applied = append(applied, m.Version)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return applied, nil
}
