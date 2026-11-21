//go:build integration

package auth

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func wantBuiltinRoles() map[string][]Permission {
	return map[string][]Permission{
		RoleAdmin: AllPermissions,
		RoleEditor: {PermInventoryCreate, PermInventoryDelete, PermInventoryEdit, PermInventoryRead,
			PermImport, PermExport, PermScanRun, PermSignatureManage},
		RoleOperator: {PermInventoryEdit, PermInventoryRead, PermExport},
		RoleViewer:   {PermInventoryRead},
	}
}

func sortedPerms(p []Permission) []Permission {
	out := slices.Clone(p)
	slices.Sort(out)
	return out
}

func checkBuiltinRoles(t *testing.T, s *Service) {
	t.Helper()
	ctx := context.Background()

	rows, err := s.store.Pool.Query(ctx, `SELECT name FROM permissions ORDER BY name`)
	if err != nil {
		t.Fatalf("query permissions: %v", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[Permission])
	if err != nil {
		t.Fatalf("collect permissions: %v", err)
	}
	if !slices.Equal(names, sortedPerms(AllPermissions)) {
		t.Fatalf("permissions table = %v, want %v", names, sortedPerms(AllPermissions))
	}

	roles, err := s.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	got := map[string]Role{}
	for _, r := range roles {
		got[r.Name] = r
	}
	for name, perms := range wantBuiltinRoles() {
		r, ok := got[name]
		if !ok {
			t.Fatalf("ListRoles has no built-in role %q: %+v", name, roles)
		}
		if !r.Builtin {
			t.Errorf("role %q Builtin = false", name)
		}
		if !slices.Equal(sortedPerms(r.Permissions), sortedPerms(perms)) {
			t.Errorf("role %q permissions = %v, want %v", name, sortedPerms(r.Permissions), sortedPerms(perms))
		}
	}
	if len(roles) != 4 {
		t.Errorf("ListRoles returned %d roles on a fresh schema, want the 4 built-in ones", len(roles))
	}
}

func TestBuiltinRolesAfterMigrate(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})

	for _, table := range []string{"users", "roles", "permissions", "role_permissions", "sessions", "audit_log"} {
		var ok bool
		if err := s.store.Pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&ok); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !ok {
			t.Fatalf("table %s missing after Migrate", table)
		}
	}
	if len(AllPermissions) != 11 {
		t.Fatalf("AllPermissions has %d entries, want 11", len(AllPermissions))
	}
	checkBuiltinRoles(t, s)

	applied, err := s.store.Migrate(ctx)
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("second Migrate applied %v, want nothing", applied)
	}
	checkBuiltinRoles(t, s)
}

func TestUsersRoleColumnRequired(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	hash := mustHash(t, goodPassword)

	_, err := s.store.Pool.Exec(ctx, `INSERT INTO users (username, password_hash) VALUES ('norole', $1)`, hash)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23502" {
		t.Fatalf("insert without role: err = %v, want not_null_violation", err)
	}
	_, err = s.store.Pool.Exec(ctx, `INSERT INTO users (username, password_hash, role) VALUES ('ghost', $1, 'nosuchrole')`, hash)
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("insert with unknown role: err = %v, want foreign_key_violation", err)
	}
	if _, err := s.store.Pool.Exec(ctx, `INSERT INTO users (username, password_hash, role) VALUES ('ok', $1, 'viewer')`, hash); err != nil {
		t.Fatalf("insert with role: %v", err)
	}
}

func TestWriteAudit(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})

	before := time.Now().Add(-time.Second)
	if err := writeAudit(ctx, s.store.Pool, "alice", auditLogin, "", "192.0.2.1"); err != nil {
		t.Fatalf("writeAudit via pool: %v", err)
	}
	err := s.store.Tx(ctx, func(tx pgx.Tx) error {
		return writeAudit(ctx, tx, "alice", auditUserCreate, "bob", "192.0.2.1")
	})
	if err != nil {
		t.Fatalf("writeAudit via tx: %v", err)
	}
	if err := s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := writeAudit(ctx, tx, "alice", auditUserDelete, "bob", "192.0.2.1"); err != nil {
			return err
		}
		return errors.New("rollback")
	}); err == nil {
		t.Fatal("rolled-back tx returned nil")
	}
	after := time.Now().Add(time.Second)

	rows, err := s.store.Pool.Query(ctx, `SELECT at, actor, action, target, address FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	type row struct {
		At      time.Time
		Actor   string
		Action  string
		Target  string
		Address string
	}
	got, err := pgx.CollectRows(rows, pgx.RowToStructByPos[row])
	if err != nil {
		t.Fatalf("collect audit_log: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("audit_log has %d rows, want 2 (rolled-back write must not persist): %+v", len(got), got)
	}
	if got[0].Action != auditLogin || got[1].Action != auditUserCreate || got[1].Target != "bob" || got[0].Actor != "alice" || got[0].Address != "192.0.2.1" {
		t.Fatalf("audit rows = %+v", got)
	}
	for _, r := range got {
		if r.At.Before(before) || r.At.After(after) {
			t.Fatalf("audit at %v outside [%v, %v]", r.At, before, after)
		}
	}
}
