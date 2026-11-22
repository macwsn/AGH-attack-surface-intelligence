//go:build integration

package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const newPassword = "battery-staple-42"

// REQ-AUTH-017
func TestListUsers(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	if users, err := s.ListUsers(ctx); err != nil || len(users) != 0 {
		t.Fatalf("ListUsers on empty table = %v, %v", users, err)
	}
	mustAddUser(t, s, "root", RoleAdmin)
	mustAddUser(t, s, "bob", RoleViewer)
	mustAddUser(t, s, "alice", RoleEditor)
	if err := s.SetUserDisabled(ctx, testActor, "bob", true); err != nil {
		t.Fatalf("SetUserDisabled: %v", err)
	}
	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	var got []string
	for _, u := range users {
		if u.CreatedAt.IsZero() {
			t.Fatalf("user %q has no created_at", u.Username)
		}
		got = append(got, fmt.Sprintf("%s/%s/%t", u.Username, u.Role, u.Disabled))
	}
	want := "alice/editor/false bob/viewer/true root/admin/false"
	if strings.Join(got, " ") != want {
		t.Fatalf("ListUsers = %v, want %s", got, want)
	}
	if u, err := s.GetUser(ctx, "bob"); err != nil || !u.Disabled {
		t.Fatalf("GetUser(bob) = %+v, %v; want disabled", u, err)
	}
}

// REQ-AUTH-018
func TestResetPassword(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	mustAddUser(t, s, "alice", RoleViewer)
	mark := lastAuditID(t, s)

	before := time.Now()
	if err := s.ResetPassword(ctx, testActor, "alice", newPassword); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	expectOneAudit(t, s, &mark, before, "user.password", "alice")
	if _, err := s.Login(ctx, "alice", goodPassword, "192.0.2.10"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("login with old password err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := s.Login(ctx, "alice", newPassword, "192.0.2.10"); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
	mark = lastAuditID(t, s)

	if err := s.ResetPassword(ctx, testActor, "alice", "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("short password err = %v, want ErrPasswordTooShort", err)
	}
	expectNoAudit(t, s, &mark, "short password")
	if err := s.ResetPassword(ctx, testActor, "ghost", newPassword); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("unknown user err = %v, want ErrUnknownUser", err)
	}
	expectNoAudit(t, s, &mark, "unknown user")

	for _, r := range auditSince(t, s, 0) {
		row := strings.Join([]string{r.Actor, r.Action, r.Target, r.Address}, "|")
		if strings.Contains(row, newPassword) || strings.Contains(row, goodPassword) {
			t.Fatalf("audit row contains a password: %+v", r)
		}
	}
}

// REQ-AUTH-019
func TestSetUserDisabled(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	mustAddUser(t, s, "root", RoleAdmin)
	mustAddUser(t, s, "alice", RoleEditor)
	sess, err := s.Login(ctx, "alice", goodPassword, "192.0.2.11")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := s.LookupSession(ctx, sess.Token); err != nil {
		t.Fatalf("LookupSession before disable: %v", err)
	}
	mark := lastAuditID(t, s)

	before := time.Now()
	if err := s.SetUserDisabled(ctx, testActor, "alice", true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	expectOneAudit(t, s, &mark, before, "user.disable", "alice")
	if _, err := s.LookupSession(ctx, sess.Token); !errors.Is(err, ErrNoSession) {
		t.Fatalf("LookupSession after disable err = %v, want ErrNoSession", err)
	}
	var sessions int
	if err := s.store.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE u.username = 'alice'`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("alice sessions after disable = %d, %v; want 0", sessions, err)
	}
	if _, err := s.Login(ctx, "alice", goodPassword, "192.0.2.11"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("login of disabled user err = %v, want ErrInvalidCredentials", err)
	}
	mark = lastAuditID(t, s)

	if err := s.SetUserDisabled(ctx, testActor, "ghost", true); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("disable unknown user err = %v, want ErrUnknownUser", err)
	}
	expectNoAudit(t, s, &mark, "disable unknown user")

	before = time.Now()
	if err := s.SetUserDisabled(ctx, testActor, "alice", false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	expectOneAudit(t, s, &mark, before, "user.enable", "alice")
	if _, err := s.Login(ctx, "alice", goodPassword, "192.0.2.11"); err != nil {
		t.Fatalf("login after enable: %v", err)
	}
}

// REQ-AUTH-019
func TestLookupSessionRejectsDisabledUser(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	mustAddUser(t, s, "alice", RoleEditor)
	sess, err := s.Login(ctx, "alice", goodPassword, "192.0.2.12")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := s.store.Pool.Exec(ctx, `UPDATE users SET disabled = true WHERE username = 'alice'`); err != nil {
		t.Fatalf("disable in db: %v", err)
	}
	if _, err := s.LookupSession(ctx, sess.Token); !errors.Is(err, ErrNoSession) {
		t.Fatalf("LookupSession of disabled user with a live session row err = %v, want ErrNoSession", err)
	}
}

// REQ-AUTH-015
func TestLastEnabledAdmin(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	mustAddUser(t, s, "root", RoleAdmin)
	mustAddUser(t, s, "root2", RoleAdmin)
	if err := s.SetUserDisabled(ctx, testActor, "root2", true); err != nil {
		t.Fatalf("disable one of two admins: %v", err)
	}
	mark := lastAuditID(t, s)

	if err := s.SetUserDisabled(ctx, testActor, "root", true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable last enabled admin err = %v, want ErrLastAdmin", err)
	}
	expectNoAudit(t, s, &mark, "disable last enabled admin")
	if err := s.SetUserRole(ctx, testActor, "root", RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last enabled admin err = %v, want ErrLastAdmin", err)
	}
	expectNoAudit(t, s, &mark, "demote last enabled admin")
	if err := s.DeleteUser(ctx, testActor, "root"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last enabled admin err = %v, want ErrLastAdmin", err)
	}
	expectNoAudit(t, s, &mark, "delete last enabled admin")
	if u, err := s.GetUser(ctx, "root"); err != nil || u.Role != RoleAdmin || u.Disabled {
		t.Fatalf("root after rejected changes = %+v, %v", u, err)
	}

	before := time.Now()
	if err := s.SetUserRole(ctx, testActor, "root2", RoleViewer); err != nil {
		t.Fatalf("demote disabled admin: %v", err)
	}
	expectOneAudit(t, s, &mark, before, "user.update", "root2")
	before = time.Now()
	if err := s.DeleteUser(ctx, testActor, "root2"); err != nil {
		t.Fatalf("delete disabled user: %v", err)
	}
	expectOneAudit(t, s, &mark, before, "user.delete", "root2")
}

// REQ-AUTH-015
func TestConcurrentDisableKeepsEnabledAdmin(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	for round := range 6 {
		a, b := fmt.Sprintf("a%d", round), fmt.Sprintf("b%d", round)
		if _, err := s.store.Pool.Exec(ctx, `UPDATE users SET role = $1`, RoleViewer); err != nil {
			t.Fatalf("reset roles: %v", err)
		}
		mustAddUser(t, s, a, RoleAdmin)
		mustAddUser(t, s, b, RoleAdmin)

		ops := []func() error{
			func() error { return s.SetUserDisabled(ctx, testActor, a, true) },
			func() error { return s.SetUserDisabled(ctx, testActor, b, true) },
		}
		switch round % 3 {
		case 1:
			ops[1] = func() error { return s.SetUserRole(ctx, testActor, b, RoleViewer) }
		case 2:
			ops[1] = func() error { return s.DeleteUser(ctx, testActor, b) }
		}
		errs := make([]error, len(ops))
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i, op := range ops {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = op()
			}()
		}
		close(start)
		wg.Wait()

		failed := 0
		for _, err := range errs {
			if err != nil {
				if !errors.Is(err, ErrLastAdmin) {
					t.Fatalf("round %d: unexpected error %v", round, err)
				}
				failed++
			}
		}
		if failed != 1 {
			t.Fatalf("round %d: %d operations failed with ErrLastAdmin, want exactly 1 (errs %v)", round, failed, errs)
		}
		if n := countUsers(t, s, "role = $1 AND NOT disabled", RoleAdmin); n != 1 {
			t.Fatalf("round %d: %d enabled admins left, want 1", round, n)
		}
	}
}

// REQ-AUTH-020
func TestListAudit(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	seed := []struct {
		min                   int
		actor, action, target string
	}{
		{0, "root", "user.create", "alice"},
		{1, "root", "user.create", "bob"},
		{2, "alice", "login", ""},
		{3, "root", "user.update", "alice"},
		{4, "bob", "login", ""},
		{5, "root", "user.delete", "bob"},
		{5, "root", "role.create", "auditor"},
	}
	for _, r := range seed {
		if _, err := s.store.Pool.Exec(ctx, `INSERT INTO audit_log (at, actor, action, target, address) VALUES ($1, $2, $3, $4, '10.0.0.1')`,
			base.Add(time.Duration(r.min)*time.Minute), r.actor, r.action, r.target); err != nil {
			t.Fatalf("seed audit: %v", err)
		}
	}
	summary := func(es []AuditEntry) string {
		var out []string
		for _, e := range es {
			out = append(out, e.Action+":"+e.Target)
			if e.Address != "10.0.0.1" || e.ID == 0 || e.At.IsZero() {
				t.Fatalf("entry fields not filled: %+v", e)
			}
		}
		return strings.Join(out, " ")
	}
	cases := []struct {
		name          string
		f             AuditFilter
		offset, limit int
		want          string
		total         int
	}{
		{"all newest first", AuditFilter{}, 0, 100, "role.create:auditor user.delete:bob login: user.update:alice login: user.create:bob user.create:alice", 7},
		{"first page", AuditFilter{}, 0, 3, "role.create:auditor user.delete:bob login:", 7},
		{"second page", AuditFilter{}, 3, 3, "user.update:alice login: user.create:bob", 7},
		{"last page", AuditFilter{}, 6, 3, "user.create:alice", 7},
		{"past the end", AuditFilter{}, 10, 3, "", 7},
		{"actor", AuditFilter{Actor: "root"}, 0, 100, "role.create:auditor user.delete:bob user.update:alice user.create:bob user.create:alice", 5},
		{"action", AuditFilter{Action: "login"}, 0, 100, "login: login:", 2},
		{"target", AuditFilter{Target: "alice"}, 0, 100, "user.update:alice user.create:alice", 2},
		{"since inclusive", AuditFilter{Since: base.Add(4 * time.Minute)}, 0, 100, "role.create:auditor user.delete:bob login:", 3},
		{"until exclusive", AuditFilter{Until: base.Add(2 * time.Minute)}, 0, 100, "user.create:bob user.create:alice", 2},
		{"range", AuditFilter{Since: base.Add(time.Minute), Until: base.Add(4 * time.Minute)}, 0, 100, "user.update:alice login: user.create:bob", 3},
		{"combined paged", AuditFilter{Actor: "root", Action: "user.create"}, 1, 1, "user.create:alice", 2},
		{"no match", AuditFilter{Actor: "nobody"}, 0, 10, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, total, err := s.ListAudit(ctx, tc.f, tc.offset, tc.limit)
			if err != nil {
				t.Fatalf("ListAudit: %v", err)
			}
			if summary(got) != tc.want || total != tc.total {
				t.Fatalf("ListAudit = %q (total %d), want %q (total %d)", summary(got), total, tc.want, tc.total)
			}
		})
	}
	for _, bad := range [][2]int{{-1, 10}, {0, 0}, {0, -5}} {
		if _, _, err := s.ListAudit(ctx, AuditFilter{}, bad[0], bad[1]); err == nil {
			t.Fatalf("ListAudit(offset %d, limit %d) succeeded, want an error", bad[0], bad[1])
		}
	}
}

func TestListAuditActions(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	if got, err := s.ListAuditActions(ctx); err != nil || len(got) != 0 {
		t.Fatalf("ListAuditActions on an empty log = %q, %v", got, err)
	}
	for _, action := range []string{"user.create", "login", "user.create", "defectdojo.export", "login"} {
		if _, err := s.store.Pool.Exec(ctx, `INSERT INTO audit_log (actor, action, target, address) VALUES ('root', $1, '', '')`, action); err != nil {
			t.Fatalf("seed audit: %v", err)
		}
	}
	got, err := s.ListAuditActions(ctx)
	if err != nil {
		t.Fatalf("ListAuditActions: %v", err)
	}
	if want := "defectdojo.export login user.create"; strings.Join(got, " ") != want {
		t.Fatalf("ListAuditActions = %q, want %q", got, want)
	}
}
