//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"asi/internal/auth"
)

// REQ-AUTH-024
func TestUserManagerCannotResetAdminPasswordOverHTTP(t *testing.T) {
	e := newRolesEnv(t)
	if err := e.svc.CreateRole(context.Background(), auth.Actor{Username: "setup", Addr: "local"}, "usermgr", []auth.Permission{auth.PermUserManage}); err != nil {
		t.Fatal(err)
	}
	e.addSession(t, "usermgr", "usermgr")
	if err := e.svc.CreateUser(context.Background(), auth.Actor{Username: "setup", Addr: "local"}, "peer", userPassword, "usermgr"); err != nil {
		t.Fatal(err)
	}
	code, _, body := e.post("usermgr", "/users/admin/password", url.Values{"password": {"mallory-password-1"}})
	if code != http.StatusForbidden {
		t.Errorf("usermgr POST /users/admin/password = %d, want 403\n%s", code, body)
	}
	if err := e.login(auth.RoleAdmin, "mallory-password-1"); err == nil {
		t.Errorf("usermgr signed in as admin with the password it set")
	}
	if err := e.login(auth.RoleAdmin, userPassword); err != nil {
		t.Errorf("admin password after rejected reset: %v", err)
	}
	mark := e.lastAudit(t)
	for _, path := range []string{"/users/editor/password", "/users/editor/disable", "/users/editor/delete", "/users/usermgr/password", "/users/usermgr/disable", "/users/usermgr/delete"} {
		if code, _, body := e.post("usermgr", path, url.Values{"password": {"mallory-password-1"}}); code != http.StatusForbidden {
			t.Errorf("usermgr POST %s = %d, want 403\n%s", path, code, body)
		}
	}
	if u := e.userNamed(t, auth.RoleAdmin); u.Disabled {
		t.Errorf("admin disabled by usermgr")
	}
	if got := e.auditAfter(t, mark); len(got) != 0 {
		t.Errorf("rejected requests wrote audit rows %q", got)
	}

	_, page := e.get("usermgr", "/users/")
	for _, action := range []string{`action="/users/admin/password"`, `action="/users/admin/disable"`, `action="/users/admin/role"`, `action="/users/usermgr/password"`, `action="/users/viewer/password"`} {
		if strings.Contains(page, action) {
			t.Errorf("usermgr Users page shows a control %s it may not use", action)
		}
	}
	if !strings.Contains(page, `action="/users/peer/password"`) {
		t.Errorf("usermgr Users page lacks the controls for peer")
	}
}
