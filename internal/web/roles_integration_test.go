//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/exchange/defectdojo"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/schedule"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

type rolesEnv struct {
	*usersEnv
	r     *Router
	runID string
}

func newRolesEnv(t *testing.T) *rolesEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
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
	inv := inventory.New(st, keys)
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "r1"})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.1"},
		Hosts: []inventory.HostResult{{Address: "10.0.0.1", Services: []inventory.ServiceResult{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}}}}); err != nil {
		t.Fatalf("RecordGroup: %v", err)
	}
	sched := &schedule.Scheduler{Store: schedule.NewStore(st, keys), Scanner: &scan.Scanner{Store: inv}, Logf: t.Logf}
	sched.Start(ctx)
	t.Cleanup(func() { cancel(); sched.Wait() })
	svc := auth.NewService(st, auth.Config{})
	dojo := &defectdojo.Service{Store: defectdojo.DBStore{DB: st, Keys: keys}, Inventory: inv, HTTP: &http.Client{}}
	r, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Users: svc, Roles: svc, Inventory: inv, Scans: sched, DefectDojo: dojo})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e := &usersEnv{h: r, svc: svc, st: st, cookies: map[string]*http.Cookie{}, csrf: map[string]string{}}
	for _, role := range []string{auth.RoleAdmin, auth.RoleEditor, auth.RoleOperator, auth.RoleViewer} {
		e.addSession(t, role, role)
	}
	return &rolesEnv{usersEnv: e, r: r, runID: fmt.Sprint(run.ID)}
}

func (e *usersEnv) addSession(t *testing.T, username, role string) {
	t.Helper()
	ctx := context.Background()
	if role != "" {
		if err := e.svc.CreateUser(ctx, auth.Actor{Username: "setup", Addr: "local"}, username, userPassword, role); err != nil {
			t.Fatalf("CreateUser %s: %v", username, err)
		}
	}
	sess, err := e.svc.Login(ctx, username, userPassword, "local")
	if err != nil {
		t.Fatalf("Login %s: %v", username, err)
	}
	e.cookies[username] = &http.Cookie{Name: auth.SessionCookieName, Value: sess.Token}
	e.csrf[username] = sess.CSRFToken
}

func (e *usersEnv) role(t *testing.T, name string) (auth.Role, bool) {
	t.Helper()
	roles, err := e.svc.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	for _, r := range roles {
		if r.Name == name {
			return r, true
		}
	}
	return auth.Role{}, false
}

func roleRowHTML(t *testing.T, body, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<tr>\s*<td><strong>` + regexp.QuoteMeta(name) + `</strong>.*?</tr>`).FindString(body)
	if m == "" {
		t.Fatalf("no row for role %q:\n%s", name, body)
	}
	return m
}

// REQ-WEB-030
func TestRolesPageMatrixAndChanges(t *testing.T) {
	e := newRolesEnv(t)
	code, body := e.get(auth.RoleAdmin, "/roles")
	if code != http.StatusOK {
		t.Fatalf("GET /roles = %d", code)
	}
	for _, p := range auth.AllPermissions {
		if !strings.Contains(body, "<th><code>"+string(p)+"</code></th>") {
			t.Errorf("matrix lacks a column for %s", p)
		}
	}
	for _, name := range []string{auth.RoleAdmin, auth.RoleEditor, auth.RoleOperator, auth.RoleViewer} {
		row := roleRowHTML(t, body, name)
		role, _ := e.role(t, name)
		if strings.Count(row, " checked disabled>") != len(role.Permissions) || strings.Count(row, `type="checkbox"`) != len(auth.AllPermissions) {
			t.Errorf("%s row ticks do not match its %d permissions:\n%s", name, len(role.Permissions), row)
		}
		if !strings.Contains(row, `<span class="tag">Built-in</span>`) || strings.Contains(row, "<form") || strings.Contains(row, "/delete") ||
			strings.Contains(row, `name="perm"`) {
			t.Errorf("built-in role %s has edit or delete controls:\n%s", name, row)
		}
	}
	if !strings.Contains(roleRowHTML(t, body, auth.RoleViewer), `aria-label="viewer: inventory.read" checked disabled>`) {
		t.Error("viewer row does not tick inventory.read")
	}
	checkPageIsSafe(t, "roles page", body)
	if strings.Contains(body, "style=") {
		t.Fatal("roles page has an inline style")
	}

	expect := func(what, action string, mark int64) {
		t.Helper()
		if got := e.auditAfter(t, mark); len(got) != 1 || got[0] != "admin "+action+" auditor 192.0.2.1" {
			t.Fatalf("%s: audit rows %q, want one %s by admin from 192.0.2.1", what, got, action)
		}
	}
	mark := e.lastAudit(t)
	code, loc, _ := e.post(auth.RoleAdmin, "/roles/create", url.Values{"name": {"auditor"}, "perm": {"inventory.read", "export"}})
	if code != http.StatusSeeOther || loc != "/roles?done=created&role=auditor" {
		t.Fatalf("create = %d %q", code, loc)
	}
	expect("create", "role.create", mark)
	if r, _ := e.role(t, "auditor"); r.Builtin || !slices.Equal(r.Permissions, []auth.Permission{"export", "inventory.read"}) {
		t.Fatalf("auditor after create = %+v", r)
	}
	_, body = e.get(auth.RoleAdmin, loc)
	row := roleRowHTML(t, body, "auditor")
	if !strings.Contains(body, "Role auditor created.") || !strings.Contains(row, `action="/roles/auditor"`) ||
		!strings.Contains(row, `href="/roles/auditor/delete"`) || strings.Count(row, `name="perm"`) != len(auth.AllPermissions) ||
		strings.Count(row, " checked>") != 2 {
		t.Fatalf("custom role row is not editable or ticks are wrong:\n%s", row)
	}

	mark = e.lastAudit(t)
	code, loc, _ = e.post(auth.RoleAdmin, "/roles/auditor", url.Values{"perm": {"inventory.read", "scan.run", "inventory.edit"}})
	if code != http.StatusSeeOther || loc != "/roles?done=saved&role=auditor" {
		t.Fatalf("update = %d %q", code, loc)
	}
	expect("update", "role.update", mark)
	if r, _ := e.role(t, "auditor"); !slices.Equal(r.Permissions, []auth.Permission{"inventory.edit", "inventory.read", "scan.run"}) {
		t.Fatalf("auditor after update = %+v", r)
	}

	if err := e.svc.CreateUser(context.Background(), auth.Actor{Username: "setup"}, "ida", userPassword, "auditor"); err != nil {
		t.Fatal(err)
	}
	inUse := `Nothing was changed: role &#34;auditor&#34; is assigned to a user. Give its users another role first.`
	mark = e.lastAudit(t)
	rejected := []struct {
		name, path string
		form       url.Values
		status     int
		want       string
	}{
		{"delete in use", "/roles/auditor/delete", url.Values{}, http.StatusConflict, inUse},
		{"edit built-in", "/roles/viewer", url.Values{"perm": {"user.manage"}}, http.StatusConflict,
			`Nothing was changed: &#34;viewer&#34; is a built-in role and cannot be edited or deleted. Create a custom role instead.`},
		{"delete built-in", "/roles/admin/delete", url.Values{}, http.StatusConflict,
			`Nothing was changed: &#34;admin&#34; is a built-in role and cannot be edited or deleted. Create a custom role instead.`},
		{"duplicate", "/roles/create", url.Values{"name": {"editor"}, "perm": {"export"}}, http.StatusConflict,
			`Role &#34;editor&#34; already exists. Choose another name.`},
		{"unknown permission", "/roles/create", url.Values{"name": {"x"}, "perm": {"root.everything"}}, http.StatusUnprocessableEntity,
			`Nothing was changed: unknown permission: &#34;root.everything&#34;. Tick only the listed permissions.`},
		{"empty name", "/roles/create", url.Values{"name": {" "}}, http.StatusUnprocessableEntity, "Enter a role name."},
		{"unknown role", "/roles/ghost", url.Values{}, http.StatusNotFound, "This role does not exist."},
	}
	for _, tc := range rejected {
		code, _, body := e.post(auth.RoleAdmin, tc.path, tc.form)
		if code != tc.status || !strings.Contains(body, tc.want) {
			t.Fatalf("%s: %d, want %d with %q:\n%s", tc.name, code, tc.status, tc.want, body)
		}
		if tc.status != http.StatusNotFound && !strings.Contains(body, `<div class="notice warn" role="alert">`+tc.want+`</div>`) {
			t.Fatalf("%s: message is not a warn notice", tc.name)
		}
	}
	if code, body := e.get(auth.RoleAdmin, "/roles/admin/delete"); code != http.StatusConflict || strings.Contains(body, "<h2>Delete role") {
		t.Fatalf("confirmation for a built-in role = %d", code)
	}
	if got := e.auditAfter(t, mark); len(got) != 0 {
		t.Fatalf("rejected changes wrote audit rows %q", got)
	}
	if r, _ := e.role(t, auth.RoleViewer); !slices.Equal(r.Permissions, []auth.Permission{"inventory.read"}) {
		t.Fatalf("viewer changed: %+v", r)
	}
	if _, ok := e.role(t, "x"); ok {
		t.Fatal("role x created by a rejected request")
	}

	if err := e.svc.DeleteUser(context.Background(), auth.Actor{Username: "setup"}, "ida"); err != nil {
		t.Fatal(err)
	}
	code, body = e.get(auth.RoleAdmin, "/roles/auditor/delete")
	if code != http.StatusOK || !strings.Contains(body, "<h2>Delete role auditor</h2>") || !strings.Contains(body, `<form method="post" action="/roles/auditor/delete">`) {
		t.Fatalf("confirmation = %d:\n%s", code, body)
	}
	if _, ok := e.role(t, "auditor"); !ok {
		t.Fatal("confirmation step deleted the role")
	}
	mark = e.lastAudit(t)
	code, loc, _ = e.post(auth.RoleAdmin, "/roles/auditor/delete", url.Values{})
	if code != http.StatusSeeOther || loc != "/roles?done=deleted&role=auditor" {
		t.Fatalf("delete = %d %q", code, loc)
	}
	expect("delete", "role.delete", mark)
	if _, ok := e.role(t, "auditor"); ok {
		t.Fatal("auditor still exists")
	}
}

// REQ-WEB-031
func TestCustomRoleGetsExactlyItsPermissions(t *testing.T) {
	e := newRolesEnv(t)
	if code, _, body := e.post(auth.RoleAdmin, "/roles/create", url.Values{"name": {"reader"}, "perm": {"inventory.read", "export"}}); code != http.StatusSeeOther {
		t.Fatalf("create role = %d\n%s", code, body)
	}
	if code, _, body := e.post(auth.RoleAdmin, "/users/create", url.Values{"username": {"rita"}, "role": {"reader"}, "password": {userPassword}}); code != http.StatusSeeOther {
		t.Fatalf("create user = %d\n%s", code, body)
	}
	e.addSession(t, "rita", "")
	granted := []auth.Permission{auth.PermInventoryRead, auth.PermExport}

	values := map[string]string{"{address}": "10.0.0.1", "{id}": e.runID, "{name}": "app.css", "{username}": "viewer", "{port}": "22", "{protocol}": "tcp", "{$}": ""}
	checked := 0
	for _, rt := range e.r.Routes() {
		key := rt.Method + " " + rt.Path
		if rt.Access.IsPublic() || key == "POST /logout" {
			continue
		}
		target := rt.Path
		for k, v := range values {
			target = strings.ReplaceAll(target, k, v)
		}
		if strings.Contains(target, "{") {
			t.Errorf("%s: no value for a path parameter", key)
			continue
		}
		var code int
		var body string
		if rt.Path == "/changes.json" {
			target += "?from=r1&to=r1"
		}
		if rt.Method == http.MethodGet {
			code, body = e.get("rita", target)
		} else {
			code, _, body = e.post("rita", target, url.Values{})
		}
		perm, gated := rt.Access.Permission()
		allowed := !gated || slices.Contains(granted, perm)
		switch {
		case allowed && rt.Method == http.MethodGet && code != http.StatusOK:
			t.Errorf("%s (%s) as reader = %d, want 200\n%.300s", key, rt.Access, code, body)
		case allowed && (code == http.StatusForbidden || code == http.StatusUnauthorized || code >= 500):
			t.Errorf("%s (%s) as reader = %d, want the action to be allowed", key, rt.Access, code)
		case !allowed && code != http.StatusForbidden:
			t.Errorf("%s (%s) as reader = %d, want 403", key, rt.Access, code)
		}
		checked++
	}
	if checked < 50 {
		t.Fatalf("walked only %d routes", checked)
	}

	_, page := e.get("rita", "/")
	nav := page[strings.Index(page, "<nav"):]
	nav = nav[:strings.Index(nav, "</nav>")]
	var got []string
	for _, m := range regexp.MustCompile(`<a href="([^"]+)"`).FindAllStringSubmatch(nav, -1) {
		got = append(got, m[1])
	}
	want := []string{"/", "/changes", "/hosts/", "/groups", "/export", "/defectdojo"}
	if !slices.Equal(got, want) {
		t.Fatalf("reader nav = %v, want %v", got, want)
	}
}

// REQ-WEB-032
func TestRolesPageOnlyForRoleManage(t *testing.T) {
	e := newRolesEnv(t)
	if _, page := e.get(auth.RoleAdmin, "/"); !strings.Contains(page, `<a href="/users/">Users</a><a href="/roles">Roles</a>`) {
		t.Fatal("admin nav lacks Roles right after Users")
	}
	n := 0
	for _, rt := range e.r.Routes() {
		if !strings.HasPrefix(rt.Path, "/roles") {
			continue
		}
		n++
		if perm, _ := rt.Access.Permission(); perm != auth.PermRoleManage {
			t.Errorf("%s %s access = %s, want role.manage", rt.Method, rt.Path, rt.Access)
		}
		target := strings.ReplaceAll(rt.Path, "{name}", "viewer")
		if rt.Path == "/roles/{name}/delete" || rt.Path == "/roles/{name}" {
			target = strings.ReplaceAll(rt.Path, "{name}", "operator")
		}
		for _, role := range []string{auth.RoleEditor, auth.RoleOperator, auth.RoleViewer} {
			if _, page := e.get(role, "/"); strings.Contains(page, `href="/roles"`) {
				t.Fatalf("%s sees the Roles nav entry", role)
			}
			var code int
			if rt.Method == http.MethodGet {
				code, _ = e.get(role, target)
			} else {
				code, _, _ = e.post(role, target, url.Values{"name": {"evil"}, "perm": {"user.manage"}})
			}
			if code != http.StatusForbidden {
				t.Errorf("%s %s as %s = %d, want 403", rt.Method, target, role, code)
			}
		}
	}
	if n != 5 {
		t.Fatalf("%d /roles routes, want list, create, update, confirm delete, delete", n)
	}
	if _, ok := e.role(t, "evil"); ok {
		t.Fatal("a forbidden request created a role")
	}
}

// REQ-AUTH-025
func TestRoleManagerCannotGrantUnheldPermissionsOrEditOwnRole(t *testing.T) {
	e := newRolesEnv(t)
	setup := auth.Actor{Username: "setup", Addr: "local"}
	for name, perms := range map[string][]auth.Permission{"rolemgr": {auth.PermRoleManage}, "nobody": nil} {
		if err := e.svc.CreateRole(context.Background(), setup, name, perms); err != nil {
			t.Fatalf("CreateRole %s: %v", name, err)
		}
	}
	e.addSession(t, "rolemgr", "rolemgr")

	for _, tc := range []struct {
		path string
		form url.Values
	}{
		{"/roles/create", url.Values{"name": {"evil"}, "perm": {"user.manage"}}},
		{"/roles/nobody", url.Values{"perm": {"inventory.read"}}},
		{"/roles/rolemgr", url.Values{"perm": {"role.manage"}}},
		{"/roles/rolemgr", url.Values{"perm": {"role.manage", "user.manage"}}},
		{"/roles/rolemgr/delete", url.Values{}},
	} {
		code, _, body := e.post("rolemgr", tc.path, tc.form)
		if code != http.StatusForbidden || !strings.Contains(body, "Nothing was changed") {
			t.Errorf("rolemgr POST %s %v = %d, want 403 with a problem\n%s", tc.path, tc.form, code, body)
		}
	}
	if _, ok := e.role(t, "evil"); ok {
		t.Error("role evil exists after a rejected create")
	}
	if r, _ := e.role(t, "nobody"); len(r.Permissions) != 0 {
		t.Errorf("nobody permissions = %v, want none", r.Permissions)
	}
	if r, ok := e.role(t, "rolemgr"); !ok || !slices.Equal(r.Permissions, []auth.Permission{auth.PermRoleManage}) {
		t.Errorf("rolemgr = %v (exists %v), want [role.manage]", r.Permissions, ok)
	}

	if code, loc, body := e.post("rolemgr", "/roles/nobody", url.Values{"perm": {"role.manage"}}); code != http.StatusSeeOther || loc != "/roles?done=saved&role=nobody" {
		t.Errorf("rolemgr POST /roles/nobody perm=role.manage = %d %q\n%s", code, loc, body)
	}
	if r, _ := e.role(t, "nobody"); !slices.Equal(r.Permissions, []auth.Permission{auth.PermRoleManage}) {
		t.Errorf("nobody permissions = %v, want [role.manage]", r.Permissions)
	}

	for _, role := range []string{auth.RoleAdmin, auth.RoleEditor, auth.RoleOperator, auth.RoleViewer} {
		if code, _, _ := e.post(auth.RoleAdmin, "/roles/"+role, url.Values{"perm": {"inventory.read"}}); code != http.StatusConflict {
			t.Errorf("admin POST /roles/%s = %d, want 409", role, code)
		}
		if code, _, _ := e.post(auth.RoleAdmin, "/roles/"+role+"/delete", url.Values{}); code != http.StatusConflict {
			t.Errorf("admin POST /roles/%s/delete = %d, want 409", role, code)
		}
	}
}

func (e *usersEnv) postCSRFHeader(user, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.Header.Set(auth.CSRFHeader, e.csrf[user])
	req.AddCookie(e.cookies[user])
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// REQ-AUTH-025
func TestRoleFormWithCSRFTokenInHeaderKeepsPermissions(t *testing.T) {
	e := newRolesEnv(t)
	if err := e.svc.CreateRole(context.Background(), auth.Actor{Username: "setup", Addr: "local"}, "nobody", nil); err != nil {
		t.Fatal(err)
	}
	want := []auth.Permission{auth.PermExport, auth.PermInventoryRead}
	form := url.Values{"perm": {"export", "inventory.read"}}
	if rec := e.postCSRFHeader(auth.RoleAdmin, "/roles/nobody", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /roles/nobody with header CSRF = %d\n%s", rec.Code, rec.Body)
	}
	if r, _ := e.role(t, "nobody"); !slices.Equal(r.Permissions, want) {
		t.Errorf("nobody permissions = %v, want %v", r.Permissions, want)
	}
	form.Set("name", "hdrrole")
	if rec := e.postCSRFHeader(auth.RoleAdmin, "/roles/create", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /roles/create with header CSRF = %d\n%s", rec.Code, rec.Body)
	}
	if r, ok := e.role(t, "hdrrole"); !ok || !slices.Equal(r.Permissions, want) {
		t.Errorf("hdrrole = %v (exists %v), want %v", r.Permissions, ok, want)
	}
	big := url.Values{"perm": {"export"}, "pad": {strings.Repeat("x", maxFormBytes)}}
	if rec := e.postCSRFHeader(auth.RoleAdmin, "/roles/nobody", big); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized role form = %d, want 400", rec.Code)
	}
	if r, _ := e.role(t, "nobody"); !slices.Equal(r.Permissions, want) {
		t.Errorf("nobody permissions after oversized form = %v, want %v", r.Permissions, want)
	}
}
