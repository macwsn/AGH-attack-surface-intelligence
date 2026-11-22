//go:build integration

package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

var testActor = Actor{Username: "root", Addr: "198.51.100.7"}

func mustAddUser(t *testing.T, s *Service, username, role string) {
	t.Helper()
	if err := s.CreateUser(context.Background(), testActor, username, goodPassword, role); err != nil {
		t.Fatalf("CreateUser(%q, %q): %v", username, role, err)
	}
}

func countUsers(t *testing.T, s *Service, where string, args ...any) int {
	t.Helper()
	var n int
	if err := s.store.Pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

func userRoles(t *testing.T, s *Service, username string) []string {
	t.Helper()
	rows, err := s.store.Pool.Query(context.Background(), `SELECT role FROM users WHERE username = $1`, username)
	if err != nil {
		t.Fatalf("query user roles: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatalf("scan role: %v", err)
		}
		out = append(out, r)
	}
	return out
}

func TestCreateUserOneRole(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	mustAddUser(t, s, "alice", RoleEditor)

	u, err := s.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u.Username != "alice" || u.Role != RoleEditor || u.CreatedAt.IsZero() {
		t.Fatalf("GetUser = %+v, want alice with role editor", u)
	}
	if got := userRoles(t, s, "alice"); len(got) != 1 || got[0] != RoleEditor {
		t.Fatalf("user rows roles = %v, want [editor]", got)
	}
	var hash string
	if err := s.store.Pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE username = 'alice'`).Scan(&hash); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	if ok, err := VerifyPassword(hash, goodPassword); err != nil || !ok {
		t.Fatalf("stored hash does not verify the password: ok=%v err=%v", ok, err)
	}
	if strings.Contains(hash, goodPassword) {
		t.Fatal("stored hash contains the plain password")
	}

	if _, err := s.GetUser(ctx, "nobody"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("GetUser(nobody) err = %v, want ErrUnknownUser", err)
	}
}

func TestCreateUserUnknownRole(t *testing.T) {
	s := newTestService(t, Config{})
	err := s.CreateUser(context.Background(), testActor, "bob", goodPassword, "superuser")
	if !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("CreateUser with unknown role err = %v, want ErrUnknownRole", err)
	}
	if !strings.Contains(err.Error(), "superuser") {
		t.Fatalf("error %q does not name the role", err)
	}
	if n := countUsers(t, s, "true"); n != 0 {
		t.Fatalf("%d users created, want 0", n)
	}
}

func TestCreateUserShortPassword(t *testing.T) {
	s := newTestService(t, Config{})
	for _, pw := range []string{"", "elevenchars", strings.Repeat("ł", 11)} {
		err := s.CreateUser(context.Background(), testActor, "carol", pw, RoleViewer)
		if !errors.Is(err, ErrPasswordTooShort) {
			t.Fatalf("CreateUser(password of %d runes) err = %v, want ErrPasswordTooShort", len([]rune(pw)), err)
		}
	}
	if n := countUsers(t, s, "true"); n != 0 {
		t.Fatalf("%d users created, want 0", n)
	}
	if err := s.CreateUser(context.Background(), testActor, "carol", strings.Repeat("ł", 12), RoleViewer); err != nil {
		t.Fatalf("CreateUser with 12 multi-byte runes: %v", err)
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	s := newTestService(t, Config{})
	mustAddUser(t, s, "alice", RoleViewer)
	err := s.CreateUser(context.Background(), testActor, "alice", goodPassword+"x", RoleAdmin)
	if !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate CreateUser err = %v, want ErrUserExists", err)
	}
	if got := userRoles(t, s, "alice"); len(got) != 1 || got[0] != RoleViewer {
		t.Fatalf("alice roles = %v after duplicate create, want [viewer]", got)
	}
}

func TestSetUserRole(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	mustAddUser(t, s, "alice", RoleViewer)

	if err := s.SetUserRole(ctx, testActor, "alice", RoleOperator); err != nil {
		t.Fatalf("SetUserRole: %v", err)
	}
	u, err := s.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u.Role != RoleOperator {
		t.Fatalf("role = %q, want operator", u.Role)
	}
	if got := userRoles(t, s, "alice"); len(got) != 1 || got[0] != RoleOperator {
		t.Fatalf("alice roles = %v, want only [operator]", got)
	}

	if err := s.SetUserRole(ctx, testActor, "alice", "nosuchrole"); !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("SetUserRole unknown role err = %v, want ErrUnknownRole", err)
	}
	if u, _ := s.GetUser(ctx, "alice"); u.Role != RoleOperator {
		t.Fatalf("role after rejected change = %q, want operator", u.Role)
	}
	if err := s.SetUserRole(ctx, testActor, "ghost", RoleViewer); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("SetUserRole unknown user err = %v, want ErrUnknownUser", err)
	}
	if err := s.DeleteUser(ctx, testActor, "ghost"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("DeleteUser unknown user err = %v, want ErrUnknownUser", err)
	}
	if err := s.DeleteUser(ctx, testActor, "alice"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := s.GetUser(ctx, "alice"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("GetUser after delete err = %v, want ErrUnknownUser", err)
	}
}

func TestUserRoleNotNull(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	hash := mustHash(t, goodPassword)
	var pgErr *pgconn.PgError

	_, err := s.store.Pool.Exec(ctx, `INSERT INTO users (username, password_hash, role) VALUES ('nullrole', $1, NULL)`, hash)
	if !errors.As(err, &pgErr) || pgErr.Code != "23502" {
		t.Fatalf("insert with NULL role: err = %v, want not_null_violation", err)
	}
	_, err = s.store.Pool.Exec(ctx, `INSERT INTO users (username, password_hash, role) VALUES ('badrole', $1, 'nosuchrole')`, hash)
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("insert with unknown role: err = %v, want foreign_key_violation", err)
	}
	mustAddUser(t, s, "alice", RoleViewer)
	_, err = s.store.Pool.Exec(ctx, `UPDATE users SET role = NULL WHERE username = 'alice'`)
	if !errors.As(err, &pgErr) || pgErr.Code != "23502" {
		t.Fatalf("clearing role: err = %v, want not_null_violation", err)
	}
}

func TestLastAdminCannotBeDeleted(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	mustAddUser(t, s, "root", RoleAdmin)
	mustAddUser(t, s, "eve", RoleViewer)

	if err := s.DeleteUser(ctx, testActor, "root"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("DeleteUser(last admin) err = %v, want ErrLastAdmin", err)
	}
	if u, err := s.GetUser(ctx, "root"); err != nil || u.Role != RoleAdmin {
		t.Fatalf("last admin after rejected delete = %+v, %v", u, err)
	}

	mustAddUser(t, s, "root2", RoleAdmin)
	if err := s.DeleteUser(ctx, testActor, "root"); err != nil {
		t.Fatalf("DeleteUser with two admins: %v", err)
	}
	if err := s.DeleteUser(ctx, testActor, "root2"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("DeleteUser(remaining admin) err = %v, want ErrLastAdmin", err)
	}
	if n := countUsers(t, s, "role = $1", RoleAdmin); n != 1 {
		t.Fatalf("%d admins, want 1", n)
	}
	if err := s.DeleteUser(ctx, testActor, "eve"); err != nil {
		t.Fatalf("DeleteUser(non-admin): %v", err)
	}
}

func TestLastAdminCannotBeDemoted(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	mustAddUser(t, s, "root", RoleAdmin)

	if err := s.SetUserRole(ctx, testActor, "root", RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("SetUserRole(last admin, viewer) err = %v, want ErrLastAdmin", err)
	}
	if u, err := s.GetUser(ctx, "root"); err != nil || u.Role != RoleAdmin {
		t.Fatalf("last admin after rejected demotion = %+v, %v", u, err)
	}
	if err := s.SetUserRole(ctx, testActor, "root", RoleAdmin); err != nil {
		t.Fatalf("SetUserRole(last admin, admin): %v", err)
	}

	mustAddUser(t, s, "root2", RoleAdmin)
	if err := s.SetUserRole(ctx, testActor, "root", RoleViewer); err != nil {
		t.Fatalf("demote one of two admins: %v", err)
	}
	if err := s.SetUserRole(ctx, testActor, "root2", RoleEditor); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote remaining admin err = %v, want ErrLastAdmin", err)
	}
	if u, _ := s.GetUser(ctx, "root2"); u.Role != RoleAdmin {
		t.Fatalf("remaining admin role = %q, want admin", u.Role)
	}
}

func TestConcurrentDemoteKeepsAdmin(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	for round := range 8 {
		a, b := fmt.Sprintf("a%d", round), fmt.Sprintf("b%d", round)
		if _, err := s.store.Pool.Exec(ctx, `UPDATE users SET role = $1`, RoleViewer); err != nil {
			t.Fatalf("reset roles: %v", err)
		}
		mustAddUser(t, s, a, RoleAdmin)
		mustAddUser(t, s, b, RoleAdmin)

		ops := []func() error{
			func() error { return s.SetUserRole(ctx, testActor, a, RoleViewer) },
			func() error { return s.SetUserRole(ctx, testActor, b, RoleViewer) },
		}
		if round%2 == 1 {
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
		if n := countUsers(t, s, "role = $1", RoleAdmin); n != 1 {
			t.Fatalf("round %d: %d admins left, want 1", round, n)
		}
	}
}

// REQ-AUTH-024
func TestUserActionsNameTheRefusal(t *testing.T) {
	ctx := context.Background()
	e, mgr := newTargetEnv(t)
	cli := Actor{Username: "cli", Addr: "local"}
	if err := e.s.SetUserDisabled(ctx, cli, "root2", true); err != nil {
		t.Fatalf("cli disable root2: %v", err)
	}
	updates := e.audits(t, auditUserUpdate) + e.audits(t, auditUserPass) + e.audits(t, auditUserEnable) + e.audits(t, auditUserDisable) + e.audits(t, auditUserDelete)
	for name, call := range map[string]func(string) error{
		"reset":   func(u string) error { return e.s.ResetPasswordKeepSession(ctx, mgr, u, otherPassword, "") },
		"disable": func(u string) error { return e.s.SetUserDisabled(ctx, mgr, u, true) },
		"enable":  func(u string) error { return e.s.SetUserDisabled(ctx, mgr, u, false) },
		"delete":  func(u string) error { return e.s.DeleteUser(ctx, mgr, u) },
		"role":    func(u string) error { return e.s.SetUserRole(ctx, mgr, u, "nobody") },
	} {
		for _, target := range []string{"root2", "viewer"} {
			if err := call(target); !errors.Is(err, ErrStrongerUser) {
				t.Errorf("usermgr %s(%s) err = %v, want ErrStrongerUser", name, target, err)
			}
		}
		if name == "role" {
			continue
		}
		if err := call("usermgr"); !errors.Is(err, ErrOwnAccount) {
			t.Errorf("usermgr %s(self) err = %v, want ErrOwnAccount", name, err)
		}
	}
	if got := e.audits(t, auditUserUpdate) + e.audits(t, auditUserPass) + e.audits(t, auditUserEnable) + e.audits(t, auditUserDisable) + e.audits(t, auditUserDelete); got != updates {
		t.Errorf("refused actions wrote %d audit rows", got-updates)
	}
	if !e.user(t, "root2").Disabled {
		t.Errorf("root2 enabled by usermgr")
	}
	root := e.signIn(t, "root")
	if err := e.s.ResetPasswordKeepSession(ctx, root, "root", otherPassword, ""); !errors.Is(err, ErrOwnAccount) {
		t.Errorf("admin reset own password err = %v, want ErrOwnAccount", err)
	}
	if err := e.s.ResetPasswordKeepSession(ctx, root, "viewer", otherPassword, ""); err != nil {
		t.Errorf("admin reset viewer password: %v", err)
	}
	if err := e.s.SetUserDisabled(ctx, root, "root2", false); err != nil {
		t.Errorf("admin enable root2: %v", err)
	}
}

// REQ-AUTH-015
func TestUserHoldingAllPermissionsCountsAsAdmin(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	if err := s.CreateRole(ctx, setupActor, "superuser", AllPermissions); err != nil {
		t.Fatalf("CreateRole superuser: %v", err)
	}
	if err := s.CreateRole(ctx, setupActor, "almost", AllPermissions[1:]); err != nil {
		t.Fatalf("CreateRole almost: %v", err)
	}
	mustAddUser(t, s, "root", RoleAdmin)
	mustAddUser(t, s, "su", "superuser")
	cli := Actor{Username: "cli", Addr: "local"}
	if err := s.SetUserRole(ctx, cli, "root", "superuser"); err != nil {
		t.Errorf("move admin to another all-permission role: %v", err)
	}
	if err := s.SetUserDisabled(ctx, cli, "root", true); err != nil {
		t.Errorf("disable one of two all-permission users: %v", err)
	}
	if err := s.SetUserRole(ctx, cli, "su", "almost"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demote last all-permission user to a role missing one permission err = %v, want ErrLastAdmin", err)
	}
}
