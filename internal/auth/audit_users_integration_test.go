//go:build integration

package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type auditEntry struct {
	At      time.Time
	Actor   string
	Action  string
	Target  string
	Address string
}

func auditEntriesAfter(t *testing.T, s *Service, afterID int64) ([]auditEntry, int64) {
	t.Helper()
	ctx := context.Background()
	rows, err := s.store.Pool.Query(ctx, `SELECT at, actor, action, target, address FROM audit_log WHERE id > $1 ORDER BY id`, afterID)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowToStructByPos[auditEntry])
	if err != nil {
		t.Fatalf("collect audit_log: %v", err)
	}
	var last int64
	if err := s.store.Pool.QueryRow(ctx, `SELECT COALESCE(max(id), 0) FROM audit_log`).Scan(&last); err != nil {
		t.Fatalf("max audit id: %v", err)
	}
	return got, last
}

func expectOneAudit(t *testing.T, s *Service, mark *int64, before time.Time, action, target string) {
	t.Helper()
	after := time.Now()
	got, last := auditEntriesAfter(t, s, *mark)
	*mark = last
	if len(got) != 1 {
		t.Fatalf("%s: %d audit rows added, want 1: %+v", action, len(got), got)
	}
	e := got[0]
	if e.Action != action || e.Target != target || e.Actor != testActor.Username || e.Address != testActor.Addr {
		t.Fatalf("%s: audit row = %+v, want action %q target %q actor %q address %q",
			action, e, action, target, testActor.Username, testActor.Addr)
	}
	if e.At.Before(before.Add(-time.Second)) || e.At.After(after.Add(time.Second)) {
		t.Fatalf("%s: audit at %v outside [%v, %v]", action, e.At, before, after)
	}
}

func expectNoAudit(t *testing.T, s *Service, mark *int64, what string) {
	t.Helper()
	got, last := auditEntriesAfter(t, s, *mark)
	*mark = last
	if len(got) != 0 {
		t.Fatalf("%s: rejected operation added audit rows %+v", what, got)
	}
}

func TestAuditUserChanges(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	var mark int64

	before := time.Now()
	mustAddUser(t, s, "root", RoleAdmin)
	expectOneAudit(t, s, &mark, before, "user.create", "root")

	before = time.Now()
	mustAddUser(t, s, "alice", RoleViewer)
	expectOneAudit(t, s, &mark, before, "user.create", "alice")

	before = time.Now()
	if err := s.SetUserRole(ctx, testActor, "alice", RoleEditor); err != nil {
		t.Fatalf("SetUserRole: %v", err)
	}
	expectOneAudit(t, s, &mark, before, "user.update", "alice")

	before = time.Now()
	if err := s.DeleteUser(ctx, testActor, "alice"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	expectOneAudit(t, s, &mark, before, "user.delete", "alice")

	if err := s.SetUserRole(ctx, testActor, "root", RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin err = %v", err)
	}
	expectNoAudit(t, s, &mark, "demote last admin")
	if err := s.DeleteUser(ctx, testActor, "root"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin err = %v", err)
	}
	expectNoAudit(t, s, &mark, "delete last admin")
	if err := s.CreateUser(ctx, testActor, "root", goodPassword, RoleViewer); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate user err = %v", err)
	}
	expectNoAudit(t, s, &mark, "duplicate user")
	if err := s.CreateUser(ctx, testActor, "bob", goodPassword, "nosuchrole"); !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("unknown role err = %v", err)
	}
	expectNoAudit(t, s, &mark, "unknown role")
	if err := s.CreateUser(ctx, testActor, "bob", "short", RoleViewer); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("short password err = %v", err)
	}
	expectNoAudit(t, s, &mark, "short password")
	if err := s.DeleteUser(ctx, testActor, "ghost"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("unknown user err = %v", err)
	}
	expectNoAudit(t, s, &mark, "delete unknown user")
}

func TestAuditRoleChanges(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	var mark int64

	before := time.Now()
	if err := s.CreateRole(ctx, testActor, "scanner", []Permission{PermScanRun}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	expectOneAudit(t, s, &mark, before, "role.create", "scanner")

	before = time.Now()
	if err := s.UpdateRole(ctx, testActor, "scanner", []Permission{PermScanRun, PermScanConfigure}); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	expectOneAudit(t, s, &mark, before, "role.update", "scanner")

	before = time.Now()
	if err := s.DeleteRole(ctx, testActor, "scanner"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	expectOneAudit(t, s, &mark, before, "role.delete", "scanner")

	if err := s.DeleteRole(ctx, testActor, RoleViewer); !errors.Is(err, ErrBuiltinRole) {
		t.Fatalf("delete built-in err = %v", err)
	}
	expectNoAudit(t, s, &mark, "delete built-in role")
	if err := s.UpdateRole(ctx, testActor, RoleEditor, nil); !errors.Is(err, ErrBuiltinRole) {
		t.Fatalf("update built-in err = %v", err)
	}
	expectNoAudit(t, s, &mark, "update built-in role")
	if err := s.CreateRole(ctx, testActor, RoleAdmin, nil); !errors.Is(err, ErrRoleExists) {
		t.Fatalf("duplicate role err = %v", err)
	}
	expectNoAudit(t, s, &mark, "duplicate role")
	if err := s.CreateRole(ctx, testActor, "x", []Permission{"nope"}); !errors.Is(err, ErrUnknownPermission) {
		t.Fatalf("unknown permission err = %v", err)
	}
	expectNoAudit(t, s, &mark, "unknown permission")

	if err := s.CreateRole(ctx, testActor, "held", nil); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	mustAddUser(t, s, "holder", "held")
	_, mark = auditEntriesAfter(t, s, mark)
	if err := s.DeleteRole(ctx, testActor, "held"); !errors.Is(err, ErrRoleInUse) {
		t.Fatalf("delete role in use err = %v", err)
	}
	expectNoAudit(t, s, &mark, "delete role in use")
}

func TestAuditUserChangesNoSecrets(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	const secret = "very-secret-password-42"
	if err := s.CreateUser(ctx, testActor, "alice", secret, RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	var hash string
	if err := s.store.Pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE username = 'alice'`).Scan(&hash); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	got, _ := auditEntriesAfter(t, s, 0)
	for _, e := range got {
		for _, field := range []string{e.Actor, e.Action, e.Target, e.Address} {
			if strings.Contains(field, secret) || strings.Contains(field, hash) || strings.Contains(field, "$argon2id$") {
				t.Fatalf("audit row %+v contains a password or hash", e)
			}
		}
	}
}
