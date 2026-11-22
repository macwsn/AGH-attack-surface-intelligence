//go:build integration

package auth

import (
	"context"
	"errors"
	"slices"
	"testing"
)

var setupActor = Actor{Username: "setup", Addr: "local"}

type escalationEnv struct {
	s *Service
}

func newEscalationEnv(t *testing.T) *escalationEnv {
	t.Helper()
	ctx := context.Background()
	s := newTestService(t, Config{})
	for name, perms := range map[string][]Permission{
		"usermgr": {PermUserManage},
		"rolemgr": {PermRoleManage},
		"nobody":  nil,
	} {
		if err := s.CreateRole(ctx, setupActor, name, perms); err != nil {
			t.Fatalf("CreateRole %s: %v", name, err)
		}
	}
	for user, role := range map[string]string{
		"root": RoleAdmin, "viewer": RoleViewer, "usermgr": "usermgr", "rolemgr": "rolemgr",
	} {
		if err := s.CreateUser(ctx, setupActor, user, goodPassword, role); err != nil {
			t.Fatalf("CreateUser %s: %v", user, err)
		}
	}
	return &escalationEnv{s: s}
}

func (e *escalationEnv) signIn(t *testing.T, username string) Actor {
	t.Helper()
	if _, err := e.s.Login(context.Background(), username, goodPassword, "192.0.2.10"); err != nil {
		t.Fatalf("Login %s: %v", username, err)
	}
	return Actor{Username: username, Addr: "192.0.2.10"}
}

func (e *escalationEnv) roleOf(t *testing.T, username string) string {
	t.Helper()
	u, err := e.s.GetUser(context.Background(), username)
	if err != nil {
		t.Fatalf("GetUser %s: %v", username, err)
	}
	return u.Role
}

func (e *escalationEnv) audits(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := e.s.store.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

func (e *escalationEnv) perms(t *testing.T, role string) ([]Permission, bool) {
	t.Helper()
	roles, err := e.s.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	for _, r := range roles {
		if r.Name == role {
			return r.Permissions, true
		}
	}
	return nil, false
}

// REQ-AUTH-024
func TestSignedInActorCannotAssignStrongerRole(t *testing.T) {
	ctx := context.Background()
	e := newEscalationEnv(t)
	mgr := e.signIn(t, "usermgr")
	updates, creates := e.audits(t, auditUserUpdate), e.audits(t, auditUserCreate)

	for _, role := range []string{RoleEditor, RoleAdmin, RoleViewer} {
		if err := e.s.SetUserRole(ctx, mgr, "viewer", role); !errors.Is(err, ErrPermissionNotHeld) {
			t.Errorf("usermgr SetUserRole(viewer, %s) err = %v, want ErrPermissionNotHeld", role, err)
		}
	}
	if got := e.roleOf(t, "viewer"); got != RoleViewer {
		t.Errorf("viewer role after rejected assignments = %q, want viewer", got)
	}
	if err := e.s.CreateUser(ctx, mgr, "mallory", goodPassword, RoleAdmin); !errors.Is(err, ErrPermissionNotHeld) {
		t.Errorf("usermgr CreateUser(admin) err = %v, want ErrPermissionNotHeld", err)
	}
	if _, err := e.s.GetUser(ctx, "mallory"); !errors.Is(err, ErrUnknownUser) {
		t.Errorf("mallory exists after rejected create: %v", err)
	}
	if e.audits(t, auditUserUpdate) != updates || e.audits(t, auditUserCreate) != creates {
		t.Errorf("rejected assignments wrote audit rows")
	}

	if err := e.s.CreateUser(ctx, setupActor, "peer", goodPassword, "usermgr"); err != nil {
		t.Fatalf("CreateUser peer: %v", err)
	}
	if err := e.s.SetUserRole(ctx, mgr, "peer", "nobody"); err != nil {
		t.Fatalf("usermgr SetUserRole(peer, nobody): %v", err)
	}
	if got := e.roleOf(t, "peer"); got != "nobody" {
		t.Errorf("peer role = %q, want nobody", got)
	}
	if err := e.s.CreateUser(ctx, mgr, "newbie", goodPassword, "usermgr"); err != nil {
		t.Errorf("usermgr CreateUser(usermgr): %v", err)
	}

	root := e.signIn(t, "root")
	if err := e.s.SetUserRole(ctx, root, "viewer", RoleEditor); err != nil {
		t.Errorf("admin SetUserRole(viewer, editor): %v", err)
	}
	if err := e.s.CreateUser(ctx, root, "root2", goodPassword, RoleAdmin); err != nil {
		t.Errorf("admin CreateUser(admin): %v", err)
	}
}

// REQ-AUTH-024
func TestSignedInActorCannotChangeOwnRole(t *testing.T) {
	ctx := context.Background()
	e := newEscalationEnv(t)
	mgr := e.signIn(t, "usermgr")
	for _, role := range []string{RoleAdmin, "nobody", "usermgr"} {
		if err := e.s.SetUserRole(ctx, mgr, "usermgr", role); !errors.Is(err, ErrOwnRole) {
			t.Errorf("usermgr SetUserRole(self, %s) err = %v, want ErrOwnRole", role, err)
		}
	}
	if got := e.roleOf(t, "usermgr"); got != "usermgr" {
		t.Errorf("usermgr role = %q after rejected self-change", got)
	}

	if err := e.s.CreateUser(ctx, setupActor, "root2", goodPassword, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	root := e.signIn(t, "root")
	if err := e.s.SetUserRole(ctx, root, "root", RoleViewer); !errors.Is(err, ErrOwnRole) {
		t.Errorf("admin SetUserRole(self, viewer) with a second admin err = %v, want ErrOwnRole", err)
	}
	if got := e.roleOf(t, "root"); got != RoleAdmin {
		t.Errorf("root role = %q, want admin", got)
	}
}

// REQ-AUTH-024
func TestPrincipalInContextMakesActorSignedIn(t *testing.T) {
	e := newEscalationEnv(t)
	ctx := WithPrincipal(context.Background(), Principal{Username: "usermgr"})
	mgr := Actor{Username: "usermgr", Addr: "192.0.2.10"}
	if err := e.s.SetUserRole(ctx, mgr, "viewer", RoleAdmin); !errors.Is(err, ErrPermissionNotHeld) {
		t.Errorf("usermgr without a session row but with a principal err = %v, want ErrPermissionNotHeld", err)
	}
	gone := Actor{Username: "ghost", Addr: "192.0.2.10"}
	ghostCtx := WithPrincipal(context.Background(), Principal{Username: "ghost"})
	if err := e.s.SetUserRole(ghostCtx, gone, "viewer", RoleAdmin); !errors.Is(err, ErrPermissionNotHeld) {
		t.Errorf("deleted signed-in actor err = %v, want ErrPermissionNotHeld", err)
	}
	if got := e.roleOf(t, "viewer"); got != RoleViewer {
		t.Errorf("viewer role = %q, want viewer", got)
	}
}

// REQ-AUTH-015
func TestLastAdminWhicheverActor(t *testing.T) {
	ctx := context.Background()
	e := newEscalationEnv(t)
	root := e.signIn(t, "root")
	mgr := e.signIn(t, "usermgr")
	cli := Actor{Username: "cli", Addr: "local"}
	for name, actor := range map[string]Actor{"root": root, "usermgr": mgr, "cli": cli} {
		if err := e.s.SetUserRole(ctx, actor, "root", RoleViewer); !errors.Is(err, ErrLastAdmin) {
			t.Errorf("%s demotes last admin err = %v, want ErrLastAdmin", name, err)
		}
		if err := e.s.SetUserDisabled(ctx, actor, "root", true); !errors.Is(err, ErrLastAdmin) {
			t.Errorf("%s disables last admin err = %v, want ErrLastAdmin", name, err)
		}
	}
	u, err := e.s.GetUser(ctx, "root")
	if err != nil || u.Role != RoleAdmin || u.Disabled {
		t.Fatalf("last admin after rejected changes = %+v, %v", u, err)
	}
}

// REQ-AUTH-024
func TestLocalActorIsExemptFromHoldRules(t *testing.T) {
	ctx := context.Background()
	e := newEscalationEnv(t)
	e.signIn(t, "usermgr")
	cli := Actor{Username: "cli", Addr: "local"}
	if err := e.s.SetUserRole(ctx, cli, "viewer", RoleAdmin); err != nil {
		t.Fatalf("cli SetUserRole(viewer, admin): %v", err)
	}
	if got := e.roleOf(t, "viewer"); got != RoleAdmin {
		t.Errorf("viewer role = %q, want admin", got)
	}
	if err := e.s.SetUserRole(ctx, Actor{Username: "usermgr", Addr: "local"}, "usermgr", RoleAdmin); err != nil {
		t.Errorf("local actor changing the role of a same-named user: %v", err)
	}
	if err := e.s.UpdateRole(ctx, cli, "nobody", AllPermissions); err != nil {
		t.Errorf("cli UpdateRole(nobody, all): %v", err)
	}
}

// REQ-AUTH-025
func TestSignedInActorRoleEdits(t *testing.T) {
	ctx := context.Background()
	e := newEscalationEnv(t)
	rm := e.signIn(t, "rolemgr")
	creates, updates, deletes := e.audits(t, auditRoleCreate), e.audits(t, auditRoleUpdate), e.audits(t, auditRoleDelete)

	if err := e.s.CreateRole(ctx, rm, "evil", []Permission{PermUserManage}); !errors.Is(err, ErrPermissionNotHeld) {
		t.Errorf("rolemgr CreateRole(evil, user.manage) err = %v, want ErrPermissionNotHeld", err)
	}
	if _, ok := e.perms(t, "evil"); ok {
		t.Errorf("role evil exists after rejected create")
	}
	if err := e.s.UpdateRole(ctx, rm, "nobody", []Permission{PermInventoryRead}); !errors.Is(err, ErrPermissionNotHeld) {
		t.Errorf("rolemgr UpdateRole(nobody, inventory.read) err = %v, want ErrPermissionNotHeld", err)
	}
	if got, _ := e.perms(t, "nobody"); len(got) != 0 {
		t.Errorf("nobody permissions = %v, want none", got)
	}
	for _, perms := range [][]Permission{{PermRoleManage}, {PermRoleManage, PermUserManage}, nil} {
		if err := e.s.UpdateRole(ctx, rm, "rolemgr", perms); !errors.Is(err, ErrOwnRole) {
			t.Errorf("rolemgr UpdateRole(self, %v) err = %v, want ErrOwnRole", perms, err)
		}
	}
	if err := e.s.DeleteRole(ctx, rm, "rolemgr"); !errors.Is(err, ErrOwnRole) {
		t.Errorf("rolemgr DeleteRole(self) err = %v, want ErrOwnRole", err)
	}
	if got, ok := e.perms(t, "rolemgr"); !ok || !slices.Equal(got, []Permission{PermRoleManage}) {
		t.Errorf("rolemgr role = %v (exists %v), want [role.manage]", got, ok)
	}
	if e.audits(t, auditRoleCreate) != creates || e.audits(t, auditRoleUpdate) != updates || e.audits(t, auditRoleDelete) != deletes {
		t.Errorf("rejected role edits wrote audit rows")
	}

	if err := e.s.UpdateRole(ctx, rm, "nobody", []Permission{PermRoleManage}); err != nil {
		t.Errorf("rolemgr UpdateRole(nobody, role.manage): %v", err)
	}
	if got, _ := e.perms(t, "nobody"); !slices.Equal(got, []Permission{PermRoleManage}) {
		t.Errorf("nobody permissions = %v, want [role.manage]", got)
	}
	if err := e.s.CreateRole(ctx, rm, "helper", []Permission{PermRoleManage}); err != nil {
		t.Errorf("rolemgr CreateRole(helper, role.manage): %v", err)
	}
	if err := e.s.DeleteRole(ctx, rm, "helper"); err != nil {
		t.Errorf("rolemgr DeleteRole(helper): %v", err)
	}

	root := e.signIn(t, "root")
	for _, role := range []string{RoleAdmin, RoleEditor, RoleOperator, RoleViewer} {
		if err := e.s.UpdateRole(ctx, root, role, []Permission{PermInventoryRead}); !errors.Is(err, ErrBuiltinRole) {
			t.Errorf("admin UpdateRole(%s) err = %v, want ErrBuiltinRole", role, err)
		}
		if err := e.s.DeleteRole(ctx, root, role); !errors.Is(err, ErrBuiltinRole) {
			t.Errorf("admin DeleteRole(%s) err = %v, want ErrBuiltinRole", role, err)
		}
	}
	if err := e.s.UpdateRole(ctx, root, "nobody", AllPermissions); err != nil {
		t.Errorf("admin UpdateRole(nobody, all): %v", err)
	}
}
