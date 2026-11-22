//go:build integration

package auth

import (
	"context"
	"errors"
	"testing"
)

const otherPassword = "another-horse-1"

func newTargetEnv(t *testing.T) (*escalationEnv, Actor) {
	t.Helper()
	e := newEscalationEnv(t)
	if err := e.s.CreateUser(context.Background(), setupActor, "root2", goodPassword, RoleAdmin); err != nil {
		t.Fatalf("CreateUser root2: %v", err)
	}
	if err := e.s.CreateUser(context.Background(), setupActor, "peer", goodPassword, "usermgr"); err != nil {
		t.Fatalf("CreateUser peer: %v", err)
	}
	return e, e.signIn(t, "usermgr")
}

func (e *escalationEnv) user(t *testing.T, username string) User {
	t.Helper()
	u, err := e.s.GetUser(context.Background(), username)
	if err != nil {
		t.Fatalf("GetUser %s: %v", username, err)
	}
	return u
}

// REQ-AUTH-024
func TestUserManagerCannotResetPasswordOfStrongerUser(t *testing.T) {
	ctx := context.Background()
	e, mgr := newTargetEnv(t)
	if err := e.s.ResetPasswordKeepSession(ctx, mgr, "root", otherPassword, ""); err == nil {
		t.Errorf("usermgr ResetPassword(root) err = nil, want a refusal")
	}
	if _, err := e.s.Login(ctx, "root", otherPassword, "192.0.2.10"); err == nil {
		t.Errorf("usermgr signed in as admin with the password it set")
	}
	if _, err := e.s.Login(ctx, "root", goodPassword, "192.0.2.10"); err != nil {
		t.Errorf("admin password after rejected reset: %v", err)
	}
	if err := e.s.ResetPasswordKeepSession(ctx, mgr, "usermgr", otherPassword, ""); err == nil {
		t.Errorf("usermgr ResetPassword(self) err = nil, want a refusal")
	}
	if err := e.s.ResetPasswordKeepSession(ctx, mgr, "viewer", otherPassword, ""); err == nil {
		t.Errorf("usermgr ResetPassword(viewer) err = nil, want a refusal: viewer holds inventory.read")
	}
	if err := e.s.ResetPasswordKeepSession(ctx, mgr, "peer", otherPassword, ""); err != nil {
		t.Errorf("usermgr ResetPassword(peer): %v", err)
	}
	if _, err := e.s.Login(ctx, "peer", otherPassword, "192.0.2.10"); err != nil {
		t.Errorf("peer login with reset password: %v", err)
	}
}

// REQ-AUTH-024
func TestUserManagerCannotDisableStrongerUser(t *testing.T) {
	ctx := context.Background()
	e, mgr := newTargetEnv(t)
	if err := e.s.SetUserDisabled(ctx, mgr, "root", true); err == nil {
		t.Errorf("usermgr SetUserDisabled(root) err = nil, want a refusal")
	}
	if e.user(t, "root").Disabled {
		t.Errorf("root disabled by usermgr")
	}
	if err := e.s.SetUserDisabled(ctx, mgr, "usermgr", true); err == nil {
		t.Errorf("usermgr SetUserDisabled(self) err = nil, want a refusal")
	}
	if err := e.s.SetUserDisabled(ctx, mgr, "peer", true); err != nil {
		t.Errorf("usermgr SetUserDisabled(peer): %v", err)
	}
	if !e.user(t, "peer").Disabled {
		t.Errorf("peer not disabled")
	}
}

// REQ-AUTH-024
func TestUserManagerCannotDeleteStrongerUser(t *testing.T) {
	ctx := context.Background()
	e, mgr := newTargetEnv(t)
	if err := e.s.DeleteUser(ctx, mgr, "root"); err == nil {
		t.Errorf("usermgr DeleteUser(root) err = nil, want a refusal")
	}
	if _, err := e.s.GetUser(ctx, "root"); err != nil {
		t.Errorf("root after rejected delete: %v", err)
	}
	if err := e.s.DeleteUser(ctx, mgr, "usermgr"); err == nil {
		t.Errorf("usermgr DeleteUser(self) err = nil, want a refusal")
	}
	if err := e.s.DeleteUser(ctx, mgr, "peer"); err != nil {
		t.Errorf("usermgr DeleteUser(peer): %v", err)
	}
	if _, err := e.s.GetUser(ctx, "peer"); !errors.Is(err, ErrUnknownUser) {
		t.Errorf("peer after delete: %v", err)
	}
}

// REQ-AUTH-024
func TestUserManagerCannotDemoteStrongerUser(t *testing.T) {
	ctx := context.Background()
	e, mgr := newTargetEnv(t)
	if err := e.s.SetUserRole(ctx, mgr, "root", "nobody"); err == nil {
		t.Errorf("usermgr SetUserRole(root, nobody) err = nil, want a refusal")
	}
	if got := e.roleOf(t, "root"); got != RoleAdmin {
		t.Errorf("root role = %q after usermgr demotion, want admin", got)
	}
	if err := e.s.SetUserRole(ctx, mgr, "usermgr", "nobody"); err == nil {
		t.Errorf("usermgr SetUserRole(self, nobody) err = nil, want a refusal")
	}
	if err := e.s.SetUserRole(ctx, mgr, "peer", "nobody"); err != nil {
		t.Errorf("usermgr SetUserRole(peer, nobody): %v", err)
	}
}

// REQ-AUTH-015
func TestLastUserHoldingAllPermissionsIsProtected(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	if err := s.CreateRole(ctx, setupActor, "superuser", AllPermissions); err != nil {
		t.Fatalf("CreateRole superuser: %v", err)
	}
	for user, role := range map[string]string{"su": "superuser", "viewer": RoleViewer} {
		if err := s.CreateUser(ctx, setupActor, user, goodPassword, role); err != nil {
			t.Fatalf("CreateUser %s: %v", user, err)
		}
	}
	cli := Actor{Username: "cli", Addr: "local"}
	if err := s.SetUserDisabled(ctx, cli, "su", true); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disable last all-permission user err = %v, want ErrLastAdmin", err)
	}
	if err := s.SetUserRole(ctx, cli, "su", RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demote last all-permission user err = %v, want ErrLastAdmin", err)
	}
	if err := s.DeleteUser(ctx, cli, "su"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("delete last all-permission user err = %v, want ErrLastAdmin", err)
	}
}

// REQ-AUTH-024
func TestOperatorWithoutActorStillManagesAdmins(t *testing.T) {
	ctx := context.Background()
	e, _ := newTargetEnv(t)
	cli := Actor{Username: "cli", Addr: "local"}
	if err := e.s.SetUserRole(ctx, cli, "root2", RoleViewer); err != nil {
		t.Errorf("cli SetUserRole(root2, viewer): %v", err)
	}
	if err := e.s.DeleteUser(ctx, cli, "root2"); err != nil {
		t.Errorf("cli DeleteUser(root2): %v", err)
	}
}
