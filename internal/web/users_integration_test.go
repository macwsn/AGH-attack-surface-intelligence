//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

const userPassword = "users-password-123"

type usersEnv struct {
	h       http.Handler
	svc     *auth.Service
	st      *store.Store
	cookies map[string]*http.Cookie
	csrf    map[string]string
}

func newUsersEnv(t *testing.T) *usersEnv {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewKeyring(master)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	svc := auth.NewService(st, auth.Config{})
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Users: svc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e := &usersEnv{h: h, svc: svc, st: st, cookies: map[string]*http.Cookie{}, csrf: map[string]string{}}
	for _, role := range []string{auth.RoleAdmin, auth.RoleEditor, auth.RoleOperator, auth.RoleViewer} {
		if err := svc.CreateUser(ctx, auth.Actor{Username: "setup", Addr: "local"}, role, userPassword, role); err != nil {
			t.Fatalf("CreateUser %s: %v", role, err)
		}
		sess, err := svc.Login(ctx, role, userPassword, "local")
		if err != nil {
			t.Fatalf("Login %s: %v", role, err)
		}
		e.cookies[role] = &http.Cookie{Name: auth.SessionCookieName, Value: sess.Token}
		e.csrf[role] = sess.CSRFToken
	}
	return e
}

func (e *usersEnv) post(role, path string, form url.Values) (int, string, string) {
	rec := postForm(e.h, path, form, e.cookies[role], e.csrf[role])
	return rec.Code, rec.Header().Get("Location"), rec.Body.String()
}

func (e *usersEnv) get(role, path string) (int, string) {
	rec := do(e.h, http.MethodGet, path, nil, e.cookies[role])
	return rec.Code, rec.Body.String()
}

func (e *usersEnv) lastAudit(t *testing.T) int64 {
	t.Helper()
	var id int64
	if err := e.st.Pool.QueryRow(context.Background(), `SELECT coalesce(max(id), 0) FROM audit_log`).Scan(&id); err != nil {
		t.Fatalf("max audit id: %v", err)
	}
	return id
}

func (e *usersEnv) auditAfter(t *testing.T, id int64) []string {
	t.Helper()
	rows, err := e.st.Pool.Query(context.Background(),
		`SELECT actor || ' ' || action || ' ' || target || ' ' || address FROM audit_log WHERE id > $1 ORDER BY id`, id)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func (e *usersEnv) login(username, password string) error {
	_, err := e.svc.Login(context.Background(), username, password, "203.0.113.5")
	return err
}

// REQ-WEB-027
func TestUsersPageAdminActions(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()

	code, body := e.get(auth.RoleAdmin, "/users/")
	if code != http.StatusOK {
		t.Fatalf("GET /users/ = %d", code)
	}
	for _, want := range []string{"<h1>Users</h1>", "<strong>viewer</strong>", `action="/users/editor/role"`,
		`<option value="operator" selected>operator</option>`, `action="/users/create"`, `href="/users/viewer/delete"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("users page lacks %q:\n%s", want, body)
		}
	}
	checkPageIsSafe(t, "users page", body)
	if strings.Contains(body, "style=") {
		t.Fatal("users page has an inline style")
	}

	const newPass, resetPass = "dave-initial-pass-1", "dave-reset-pass-22"
	steps := []struct {
		name   string
		path   string
		form   url.Values
		done   string
		action string
		check  func() error
	}{
		{"create", "/users/create", url.Values{"username": {"dave"}, "role": {auth.RoleEditor}, "password": {newPass}}, "created", "user.create",
			func() error { return e.login("dave", newPass) }},
		{"change role", "/users/dave/role", url.Values{"role": {auth.RoleOperator}}, "role", "user.update",
			func() error {
				if u, err := e.svc.GetUser(ctx, "dave"); err != nil || u.Role != auth.RoleOperator {
					return errors.New("role not changed")
				}
				return nil
			}},
		{"reset password", "/users/dave/password", url.Values{"password": {resetPass}}, "password", "user.password",
			func() error {
				if e.login("dave", newPass) == nil {
					return errors.New("old password still works")
				}
				return e.login("dave", resetPass)
			}},
		{"disable", "/users/dave/disable", url.Values{}, "disabled", "user.disable",
			func() error {
				if e.login("dave", resetPass) == nil {
					return errors.New("disabled user can log in")
				}
				return nil
			}},
		{"enable", "/users/dave/enable", url.Values{}, "enabled", "user.enable",
			func() error { return e.login("dave", resetPass) }},
	}
	for _, s := range steps {
		mark := e.lastAudit(t)
		code, loc, body := e.post(auth.RoleAdmin, s.path, s.form)
		if code != http.StatusSeeOther || loc != "/users/?done="+s.done+"&user=dave" {
			t.Fatalf("%s: %d Location %q\n%s", s.name, code, loc, body)
		}
		if got := e.auditAfter(t, mark); len(got) != 1 || got[0] != "admin "+s.action+" dave 192.0.2.1" {
			t.Fatalf("%s: audit rows %q, want one %q by admin from 192.0.2.1", s.name, got, s.action)
		}
		if err := s.check(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if _, page := e.get(auth.RoleAdmin, loc); !strings.Contains(page, `<div class="notice ok" role="status">`) {
			t.Fatalf("%s: no confirmation on the page after redirect", s.name)
		}
	}
	if _, page := e.get(auth.RoleAdmin, "/users/?done=disabled&user=dave"); !strings.Contains(page, "User dave disabled.") {
		t.Fatalf("disable confirmation missing:\n%s", page)
	}

	mark := e.lastAudit(t)
	code, body = e.get(auth.RoleAdmin, "/users/dave/delete")
	if code != http.StatusOK || !strings.Contains(body, "<h2>Delete user dave</h2>") ||
		!strings.Contains(body, `<form method="post" action="/users/dave/delete">`) {
		t.Fatalf("confirmation page = %d:\n%s", code, body)
	}
	if _, err := e.svc.GetUser(ctx, "dave"); err != nil {
		t.Fatalf("the confirmation step deleted the user: %v", err)
	}
	if got := e.auditAfter(t, mark); len(got) != 0 {
		t.Fatalf("confirmation step wrote audit rows %q", got)
	}
	code, loc, _ := e.post(auth.RoleAdmin, "/users/dave/delete", url.Values{})
	if code != http.StatusSeeOther || loc != "/users/?done=deleted&user=dave" {
		t.Fatalf("delete = %d %q", code, loc)
	}
	if _, err := e.svc.GetUser(ctx, "dave"); !errors.Is(err, auth.ErrUnknownUser) {
		t.Fatalf("dave after delete: %v", err)
	}
	if got := e.auditAfter(t, mark); len(got) != 1 || got[0] != "admin user.delete dave 192.0.2.1" {
		t.Fatalf("delete audit rows %q", got)
	}
	if code, _ := e.get(auth.RoleAdmin, "/users/dave/delete"); code != http.StatusNotFound {
		t.Fatalf("confirmation for a deleted user = %d, want 404", code)
	}
}

// REQ-WEB-028
func TestUsersPageRejectedChanges(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	lastAdmin := `Nothing was changed: &#34;admin&#34; is the last enabled admin. Make another user an admin first.`
	cases := []struct {
		name   string
		path   string
		form   url.Values
		status int
		want   string
	}{
		{"demote last admin", "/users/admin/role", url.Values{"role": {auth.RoleViewer}}, http.StatusConflict, lastAdmin},
		{"disable last admin", "/users/admin/disable", url.Values{}, http.StatusConflict, lastAdmin},
		{"delete last admin", "/users/admin/delete", url.Values{}, http.StatusConflict, lastAdmin},
		{"duplicate user", "/users/create", url.Values{"username": {"viewer"}, "role": {auth.RoleViewer}, "password": {userPassword}},
			http.StatusConflict, `User &#34;viewer&#34; already exists. Choose another username.`},
		{"short password", "/users/create", url.Values{"username": {"erin"}, "role": {auth.RoleViewer}, "password": {"short"}},
			http.StatusUnprocessableEntity, "Nothing was changed: the password must be at least 12 characters."},
		{"short reset", "/users/viewer/password", url.Values{"password": {"short"}},
			http.StatusUnprocessableEntity, "Nothing was changed: the password must be at least 12 characters."},
		{"unknown role on create", "/users/create", url.Values{"username": {"erin"}, "role": {"superuser"}, "password": {userPassword}},
			http.StatusUnprocessableEntity, `Nothing was changed: role &#34;superuser&#34; does not exist.`},
		{"unknown role on change", "/users/viewer/role", url.Values{"role": {"superuser"}},
			http.StatusUnprocessableEntity, `Nothing was changed: role &#34;superuser&#34; does not exist.`},
		{"empty username", "/users/create", url.Values{"username": {"  "}, "role": {auth.RoleViewer}, "password": {userPassword}},
			http.StatusUnprocessableEntity, "Enter a username."},
		{"unknown user", "/users/ghost/disable", url.Values{}, http.StatusNotFound, "This user does not exist."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mark := e.lastAudit(t)
			code, _, body := e.post(auth.RoleAdmin, tc.path, tc.form)
			if code != tc.status || !strings.Contains(body, tc.want) {
				t.Fatalf("%d, want %d with %q:\n%s", code, tc.status, tc.want, body)
			}
			if tc.status != http.StatusNotFound && !strings.Contains(body, `<div class="notice warn" role="alert">`+tc.want+`</div>`) {
				t.Fatalf("message is not a warn notice on the users page:\n%s", body)
			}
			if got := e.auditAfter(t, mark); len(got) != 0 {
				t.Fatalf("rejected change wrote audit rows %q", got)
			}
		})
	}
	u, err := e.svc.GetUser(ctx, auth.RoleAdmin)
	if err != nil || u.Role != auth.RoleAdmin || u.Disabled {
		t.Fatalf("last admin after rejected changes = %+v, %v", u, err)
	}
	if err := e.login(auth.RoleAdmin, userPassword); err != nil {
		t.Fatalf("last admin cannot log in: %v", err)
	}
	if _, err := e.svc.GetUser(ctx, "erin"); !errors.Is(err, auth.ErrUnknownUser) {
		t.Fatalf("erin was created by a rejected request: %v", err)
	}
	if err := e.login(auth.RoleViewer, userPassword); err != nil {
		t.Fatalf("viewer password changed by a rejected reset: %v", err)
	}
}

// REQ-WEB-029
func TestUsersPageOnlyForUserManage(t *testing.T) {
	e := newUsersEnv(t)
	_, admin := e.get(auth.RoleAdmin, "/")
	if !strings.Contains(admin, `<a href="/users/">Users</a>`) {
		t.Fatalf("admin nav lacks Users:\n%s", admin)
	}
	nav := admin[strings.Index(admin, "<nav"):]
	nav = nav[:strings.Index(nav, "</nav>")]
	if strings.Index(nav, `<a href="/users/">Users</a>`) < strings.Index(nav, `<a href="/defectdojo">DefectDojo</a>`) {
		t.Fatalf("Users is not after the existing nav entries:\n%s", nav)
	}
	if !strings.Contains(nav, `<h2 class="nav-heading">Administration</h2><a href="/users/">Users</a>`) {
		t.Fatalf("Users does not open the Administration group:\n%s", nav)
	}
	for _, role := range []string{auth.RoleEditor, auth.RoleOperator, auth.RoleViewer} {
		if _, page := e.get(role, "/"); strings.Contains(page, `href="/users/"`) {
			t.Fatalf("%s sees the Users nav entry", role)
		}
	}

	r := e.h.(*Router)
	n := 0
	for _, rt := range r.Routes() {
		if !strings.HasPrefix(rt.Path, "/users") {
			continue
		}
		n++
		if perm, _ := rt.Access.Permission(); perm != auth.PermUserManage {
			t.Errorf("%s %s access = %s, want user.manage", rt.Method, rt.Path, rt.Access)
		}
		target := strings.TrimSuffix(strings.ReplaceAll(rt.Path, "{username}", "viewer"), "{$}")
		for _, role := range []string{auth.RoleEditor, auth.RoleOperator, auth.RoleViewer} {
			var code int
			if rt.Method == http.MethodGet {
				code, _ = e.get(role, target)
			} else {
				code, _, _ = e.post(role, target, url.Values{"role": {auth.RoleAdmin}, "password": {"stolen-password-1"},
					"username": {"mallory"}})
			}
			if code != http.StatusForbidden {
				t.Errorf("%s %s as %s = %d, want 403", rt.Method, target, role, code)
			}
		}
	}
	if n != 8 {
		t.Fatalf("%d /users routes, want list, create, role, password, disable, enable, confirm delete, delete", n)
	}
	if u, err := e.svc.GetUser(context.Background(), auth.RoleViewer); err != nil || u.Role != auth.RoleViewer || u.Disabled {
		t.Fatalf("viewer changed by forbidden requests: %+v, %v", u, err)
	}
	if _, err := e.svc.GetUser(context.Background(), "mallory"); !errors.Is(err, auth.ErrUnknownUser) {
		t.Fatalf("forbidden create made a user: %v", err)
	}
	if code, _, _ := e.post(auth.RoleAdmin, "/users/viewer/disable", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("admin disable = %d", code)
	}
	if code, _, _ := (&usersEnv{h: e.h, cookies: e.cookies, csrf: map[string]string{}}).post(auth.RoleAdmin, "/users/viewer/enable", url.Values{}); code != http.StatusForbidden {
		t.Fatalf("POST without CSRF token = %d, want 403", code)
	}
}

// REQ-AUTH-018
func TestPasswordResetEndsSessionsOfThatUser(t *testing.T) {
	e := newUsersEnv(t)
	if code, _ := e.get(auth.RoleViewer, "/hosts/"); code != http.StatusOK {
		t.Fatalf("viewer GET /hosts/ before reset = %d, want 200", code)
	}
	mark := e.lastAudit(t)
	code, loc, body := e.post(auth.RoleAdmin, "/users/viewer/password", url.Values{"password": {"viewer-reset-pass-9"}})
	if code != http.StatusSeeOther || loc != "/users/?done=password&user=viewer" {
		t.Fatalf("reset password: %d Location %q\n%s", code, loc, body)
	}
	if got := e.auditAfter(t, mark); len(got) != 1 || got[0] != "admin user.password viewer 192.0.2.1" {
		t.Fatalf("reset password audit rows %q", got)
	}
	rec := do(e.h, http.MethodGet, "/hosts/", nil, e.cookies[auth.RoleViewer])
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
		t.Fatalf("session from before the password reset still valid: GET /hosts/ = %d Location %q, want 303 to /login",
			rec.Code, rec.Header().Get("Location"))
	}
	if code, _ := e.get(auth.RoleEditor, "/hosts/"); code != http.StatusOK {
		t.Fatalf("other user's session ended by the reset: GET /hosts/ = %d", code)
	}
}

// REQ-AUTH-018
func TestOwnPasswordResetKeepsOnlyCurrentSession(t *testing.T) {
	e := newUsersEnv(t)
	other, err := e.svc.Login(context.Background(), auth.RoleAdmin, userPassword, "local")
	if err != nil {
		t.Fatalf("second admin login: %v", err)
	}
	otherCookie := &http.Cookie{Name: auth.SessionCookieName, Value: other.Token}
	mark := e.lastAudit(t)
	code, _, body := e.post(auth.RoleAdmin, "/users/admin/password", url.Values{"password": {"admin-reset-pass-9"}})
	if code != http.StatusForbidden || !strings.Contains(body, "Account page") {
		t.Fatalf("reset own password through /users: %d, want 403 pointing to the Account page\n%s", code, body)
	}
	if got := e.auditAfter(t, mark); len(got) != 0 {
		t.Fatalf("rejected own reset audit rows %q", got)
	}
	if code, _ := e.get(auth.RoleAdmin, "/users/"); code != http.StatusOK {
		t.Fatalf("current session ended by a rejected own reset: GET /users/ = %d", code)
	}
	if rec := do(e.h, http.MethodGet, "/users/", nil, otherCookie); rec.Code != http.StatusOK {
		t.Fatalf("other session ended by a rejected own reset: GET /users/ = %d", rec.Code)
	}
	if err := e.login(auth.RoleAdmin, userPassword); err != nil {
		t.Fatalf("admin password after rejected own reset: %v", err)
	}
}

func (e *usersEnv) userNamed(t *testing.T, username string) auth.User {
	t.Helper()
	u, err := e.svc.GetUser(context.Background(), username)
	if err != nil {
		t.Fatalf("GetUser %s: %v", username, err)
	}
	return u
}

// REQ-AUTH-024
func TestUserManagerCannotEscalateThroughRoleAssignment(t *testing.T) {
	e := newRolesEnv(t)
	setup := auth.Actor{Username: "setup", Addr: "local"}
	for name, perms := range map[string][]auth.Permission{"usermgr": {auth.PermUserManage}, "nobody": nil} {
		if err := e.svc.CreateRole(context.Background(), setup, name, perms); err != nil {
			t.Fatalf("CreateRole %s: %v", name, err)
		}
	}
	e.addSession(t, "usermgr", "usermgr")
	mark := e.lastAudit(t)

	for _, tc := range []struct{ path, role string }{
		{"/users/viewer/role", auth.RoleEditor},
		{"/users/viewer/role", auth.RoleAdmin},
		{"/users/usermgr/role", auth.RoleAdmin},
		{"/users/usermgr/role", "nobody"},
	} {
		code, _, body := e.post("usermgr", tc.path, url.Values{"role": {tc.role}})
		if code != http.StatusForbidden || !strings.Contains(body, "Nothing was changed") {
			t.Errorf("usermgr POST %s role=%s = %d, want 403 with a problem\n%s", tc.path, tc.role, code, body)
		}
	}
	code, _, _ := e.post("usermgr", "/users/create", url.Values{"username": {"mallory"}, "password": {"mallory-password-1"}, "role": {auth.RoleAdmin}})
	if code != http.StatusForbidden {
		t.Errorf("usermgr POST /users/create role=admin = %d, want 403", code)
	}
	if _, err := e.svc.GetUser(context.Background(), "mallory"); !errors.Is(err, auth.ErrUnknownUser) {
		t.Errorf("mallory created by a rejected request: %v", err)
	}
	if got := e.userNamed(t, "viewer").Role; got != auth.RoleViewer {
		t.Errorf("viewer role = %q, want viewer", got)
	}
	if got := e.userNamed(t, "usermgr").Role; got != "usermgr" {
		t.Errorf("usermgr role = %q, want usermgr", got)
	}
	if got := e.auditAfter(t, mark); len(got) != 0 {
		t.Errorf("rejected assignments wrote audit rows %q", got)
	}

	if err := e.svc.CreateUser(context.Background(), setup, "peer", userPassword, "usermgr"); err != nil {
		t.Fatalf("CreateUser peer: %v", err)
	}
	if code, loc, body := e.post("usermgr", "/users/peer/role", url.Values{"role": {"nobody"}}); code != http.StatusSeeOther || loc != "/users/?done=role&user=peer" {
		t.Errorf("usermgr POST /users/peer/role role=nobody = %d %q\n%s", code, loc, body)
	}
	if got := e.userNamed(t, "peer").Role; got != "nobody" {
		t.Errorf("peer role = %q, want nobody", got)
	}
	if code, _, body := e.post(auth.RoleAdmin, "/users/viewer/role", url.Values{"role": {auth.RoleEditor}}); code != http.StatusSeeOther {
		t.Errorf("admin POST /users/viewer/role role=editor = %d\n%s", code, body)
	}
	if got := e.userNamed(t, "viewer").Role; got != auth.RoleEditor {
		t.Errorf("viewer role = %q, want editor", got)
	}
}

// REQ-AUTH-015
func TestLastAdminCannotBeDemotedOrDisabledOverHTTP(t *testing.T) {
	e := newRolesEnv(t)
	if err := e.svc.CreateRole(context.Background(), auth.Actor{Username: "setup", Addr: "local"}, "usermgr", []auth.Permission{auth.PermUserManage}); err != nil {
		t.Fatal(err)
	}
	e.addSession(t, "usermgr", "usermgr")
	for _, actor := range []string{auth.RoleAdmin, "usermgr"} {
		for _, tc := range []struct {
			path string
			form url.Values
		}{
			{"/users/admin/role", url.Values{"role": {auth.RoleViewer}}},
			{"/users/admin/disable", url.Values{}},
		} {
			if code, _, body := e.post(actor, tc.path, tc.form); code == http.StatusSeeOther || code < 400 {
				t.Errorf("%s POST %s = %d, want a rejection\n%s", actor, tc.path, code, body)
			}
		}
	}
	if u := e.userNamed(t, auth.RoleAdmin); u.Role != auth.RoleAdmin || u.Disabled {
		t.Errorf("last admin after rejected changes = %+v", u)
	}
}

// REQ-AUTH-024
func TestUsersPageOffersControlsOnlyForManageableRows(t *testing.T) {
	e := newRolesEnv(t)
	if err := e.svc.CreateRole(context.Background(), auth.Actor{Username: "setup", Addr: "local"}, "usermgr", []auth.Permission{auth.PermUserManage, auth.PermInventoryRead}); err != nil {
		t.Fatal(err)
	}
	e.addSession(t, "usermgr", "usermgr")
	_, page := e.get(auth.RoleAdmin, "/users/")
	if strings.Contains(page, `action="/users/admin/password"`) || strings.Contains(page, `href="/users/admin/delete"`) {
		t.Errorf("admin Users page offers controls on the admin's own row")
	}
	if !strings.Contains(page, `href="/account"`) {
		t.Errorf("admin Users page does not point to the Account page for the own password")
	}
	for _, action := range []string{`action="/users/viewer/password"`, `action="/users/editor/disable"`, `action="/users/usermgr/role"`} {
		if !strings.Contains(page, action) {
			t.Errorf("admin Users page lacks %s", action)
		}
	}
	if !strings.Contains(page, "You can manage only users whose role you fully hold") {
		t.Errorf("Users page does not explain which users can be managed")
	}
	if regexp.MustCompile(`style\s*=`).MatchString(page) {
		t.Errorf("Users page has a style attribute")
	}

	_, page = e.get("usermgr", "/users/")
	if !strings.Contains(page, `action="/users/viewer/password"`) || strings.Contains(page, `action="/users/editor/password"`) {
		t.Errorf("usermgr with inventory.read: want controls for viewer only, not for editor")
	}
	code, _, body := e.post("usermgr", "/users/editor/role", url.Values{"role": {auth.RoleViewer}})
	if code != http.StatusForbidden || !strings.Contains(body, `user &#34;editor&#34; has permissions your role does not have`) {
		t.Errorf("usermgr POST /users/editor/role = %d, want 403 naming editor\n%s", code, body)
	}
	if code, _, body := e.post("usermgr", "/users/viewer/disable", url.Values{}); code != http.StatusSeeOther {
		t.Errorf("usermgr with inventory.read POST /users/viewer/disable = %d, want 303\n%s", code, body)
	}
	if code, _, body := e.post("usermgr", "/users/viewer/enable", url.Values{}); code != http.StatusSeeOther {
		t.Errorf("usermgr with inventory.read POST /users/viewer/enable = %d, want 303\n%s", code, body)
	}
}
