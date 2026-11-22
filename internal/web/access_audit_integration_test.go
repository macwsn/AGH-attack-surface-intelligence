//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/exchange/defectdojo"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/scan"
	"asi/internal/schedule"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

const (
	auditHost  = "10.0.0.1"
	auditTitle = "Audit Leak Portal"
	auditRun   = "audit-run-seven"
)

type leakEnv struct {
	*usersEnv
	r      *Router
	runID  string
	huntID string
}

var auditRoles = map[string][]auth.Permission{
	"nobody":    nil,
	"exporter":  {auth.PermExport},
	"sigonly":   {auth.PermSignatureManage},
	"sigreader": {auth.PermSignatureManage, auth.PermInventoryRead},
	"usermgr":   {auth.PermUserManage},
	"rolemgr":   {auth.PermRoleManage},
	"creator":   {auth.PermInventoryCreate},
	"deleter":   {auth.PermInventoryDelete},
	"editonly":  {auth.PermInventoryEdit},
	"dojocfg":   {auth.PermScanConfigure},
}

func newLeakEnv(t *testing.T) *leakEnv {
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
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: auditRun})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: []string{auditHost},
		Hosts: []inventory.HostResult{{Address: auditHost, Services: []inventory.ServiceResult{
			{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"},
			{Port: 80, Protocol: "tcp", State: "open", Service: "http",
				HTTP: &probe.HTTP{Scheme: "http", URL: "http://" + auditHost + "/", StatusCode: 200, Title: auditTitle, Headers: map[string]string{}},
				Body: []byte("<p>" + auditTitle + "</p>")},
		}}}}); err != nil {
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
	setup := auth.Actor{Username: "setup", Addr: "local"}
	for name, perms := range auditRoles {
		if err := svc.CreateRole(ctx, setup, name, perms); err != nil {
			t.Fatalf("CreateRole %s: %v", name, err)
		}
		e.addSession(t, name, name)
	}
	env := &leakEnv{usersEnv: e, r: r, runID: fmt.Sprint(run.ID)}
	sig := "id: auditportal\nname: Audit portal\nkind: technology\nconfidence: 90\nmatch:\n  all:\n    - {type: title_regex, value: 'Audit Leak'}\n"
	code, loc, body := e.post(auth.RoleAdmin, "/signatures/hunt", url.Values{"source": {sig}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/signatures/hunts/") {
		t.Fatalf("admin hunt = %d %q\n%.400s", code, loc, body)
	}
	env.huntID = strings.TrimPrefix(loc, "/signatures/hunts/")
	return env
}

func (e *leakEnv) leaks(body string) []string {
	var got []string
	for _, s := range []string{auditHost, auditTitle, auditRun} {
		if strings.Contains(body, s) {
			got = append(got, s)
		}
	}
	return got
}

// AC1: the dashboard shows no inventory data to a role without inventory.read.
func TestAuditDashboardHidesInventoryWithoutRead(t *testing.T) {
	e := newLeakEnv(t)
	for _, role := range []string{"nobody", "exporter"} {
		code, body := e.get(role, "/")
		if code != http.StatusOK {
			t.Errorf("GET / as %s = %d, want 200 with a short message", role, code)
		}
		if got := e.leaks(body); len(got) > 0 {
			t.Errorf("GET / as %s (no inventory.read) shows inventory data %q", role, got)
		}
	}
	if _, body := e.get(auth.RoleViewer, "/"); !strings.Contains(body, auditHost) {
		t.Errorf("GET / as viewer no longer shows the seeded host")
	}
}

// AC2: a user manager cannot assign a role stronger than their own, nor change their own role.
func TestAuditUserManagerCannotEscalateThroughRoleAssignment(t *testing.T) {
	e := newLeakEnv(t)
	if code, _, _ := e.post("usermgr", "/users/usermgr/role", url.Values{"role": {auth.RoleAdmin}}); code != http.StatusForbidden {
		t.Errorf("self-promotion to admin = %d, want 403", code)
	}
	if code, _, _ := e.post("usermgr", "/users/viewer/role", url.Values{"role": {auth.RoleEditor}}); code != http.StatusForbidden {
		t.Errorf("assigning a stronger role (editor) = %d, want 403", code)
	}
	if u := e.userRole(t, "usermgr"); u != "usermgr" {
		t.Errorf("usermgr role after rejected requests = %q", u)
	}
	if u := e.userRole(t, auth.RoleViewer); u != auth.RoleViewer {
		t.Errorf("viewer role after rejected requests = %q", u)
	}
	if err := e.svc.CreateUser(context.Background(), auth.Actor{Username: "setup", Addr: "local"}, "peer", userPassword, "usermgr"); err != nil {
		t.Fatalf("CreateUser peer: %v", err)
	}
	if code, _, body := e.post("usermgr", "/users/peer/role", url.Values{"role": {"nobody"}}); code != http.StatusSeeOther {
		t.Errorf("legal assignment of a weaker role = %d, want 303\n%.300s", code, body)
	}
	if u := e.userRole(t, "peer"); u != "nobody" {
		t.Errorf("peer role after a legal assignment = %q, want nobody", u)
	}
}

func (e *usersEnv) userRole(t *testing.T, username string) string {
	t.Helper()
	u, err := e.svc.GetUser(context.Background(), username)
	if err != nil {
		t.Fatalf("GetUser %s: %v", username, err)
	}
	return u.Role
}

// AC3: a role manager can grant only permissions they hold and cannot edit their own role.
func TestAuditRoleManagerCannotGrantUnheldPermissions(t *testing.T) {
	e := newLeakEnv(t)
	if code, _, _ := e.post("rolemgr", "/roles/rolemgr", url.Values{"perm": {"role.manage", "user.manage", "inventory.read"}}); code != http.StatusForbidden {
		t.Errorf("self-grant on own role = %d, want 403", code)
	}
	if r, _ := e.role(t, "rolemgr"); !slices.Equal(r.Permissions, []auth.Permission{auth.PermRoleManage}) {
		t.Errorf("rolemgr permissions after self-grant = %v", r.Permissions)
	}
	if code, _, _ := e.post("rolemgr", "/roles/create", url.Values{"name": {"evil"}, "perm": {"user.manage"}}); code != http.StatusForbidden {
		t.Errorf("creating a role with an unheld permission = %d, want 403", code)
	}
	if code, _, _ := e.post("rolemgr", "/roles/nobody", url.Values{"perm": {"inventory.read"}}); code != http.StatusForbidden {
		t.Errorf("granting an unheld permission to another role = %d, want 403", code)
	}
	if _, ok := e.role(t, "evil"); ok {
		t.Error("role evil was created")
	}
}

// AC4: hunts and tests on stored data need inventory.read, the CSV export, record inventory.edit.
func TestAuditSignatureManageAloneCannotReadInventory(t *testing.T) {
	e := newLeakEnv(t)
	sig := "id: probe2\nname: Probe\nkind: technology\nconfidence: 90\nmatch:\n  all:\n    - {type: title_regex, value: 'Audit'}\n"
	if code, _, body := e.post("sigonly", "/signatures/test", url.Values{"source": {sig}, "address": {auditHost}, "port": {"80"}, "protocol": {"tcp"}}); code != http.StatusForbidden {
		t.Errorf("POST /signatures/test as signature.manage only = %d, want 403 (leaks %q)", code, e.leaks(body))
	}
	if code, _, _ := e.post("sigonly", "/signatures/hunt", url.Values{"source": {sig}}); code != http.StatusForbidden {
		t.Errorf("POST /signatures/hunt as signature.manage only = %d, want 403", code)
	}
	hunt := "/signatures/hunts/" + e.huntID
	if code, body := e.get("sigonly", hunt); code != http.StatusForbidden {
		t.Errorf("GET %s as signature.manage only = %d, want 403 (leaks %q)", hunt, code, e.leaks(body))
	}
	if code, _ := e.get("sigreader", hunt+"/csv"); code != http.StatusForbidden {
		t.Errorf("GET %s/csv without export = %d, want 403", hunt, code)
	}
	if code, _, _ := e.post("sigonly", hunt+"/save", url.Values{}); code != http.StatusForbidden {
		t.Errorf("POST %s/save as signature.manage only = %d, want 403", hunt, code)
	}
	if code, _, _ := e.post("sigreader", hunt+"/save", url.Values{"record": {"1"}}); code != http.StatusForbidden {
		t.Errorf("POST %s/save record without inventory.edit = %d, want 403", hunt, code)
	}
}

// AC5: host entry, delete confirmations and an invalid edit do not show host data without inventory.read.
func TestAuditHostPagesNeedInventoryRead(t *testing.T) {
	e := newLeakEnv(t)
	existing, body := e.get("creator", "/hosts/entry?address="+auditHost)
	missing, _ := e.get("creator", "/hosts/entry?address=10.9.9.9")
	if existing != missing {
		t.Errorf("GET /hosts/entry without inventory.read: existing address = %d, missing = %d, want the same answer", existing, missing)
	}
	if strings.Contains(body, "ssh") || strings.Contains(body, auditTitle) {
		t.Errorf("GET /hosts/entry shows an existing host to a role without inventory.read")
	}
	for _, path := range []string{"/hosts/" + auditHost + "/delete", "/hosts/" + auditHost + "/services/22/tcp/delete"} {
		if code, body := e.get("deleter", path); code != http.StatusForbidden {
			t.Errorf("GET %s as inventory.delete only = %d, want 403 (leaks %q)", path, code, e.leaks(body))
		}
	}
	code, _, body := e.post("editonly", "/hosts/"+auditHost, url.Values{"tags": {strings.Repeat("x", 500)}})
	if code == http.StatusUnprocessableEntity || strings.Contains(body, auditTitle) || strings.Contains(body, auditRun) {
		t.Errorf("invalid POST /hosts/%s as inventory.edit only = %d and renders the host page", auditHost, code)
	}
}

// AC6: saving DefectDojo settings does not render the export-only page; roles.go reads the form with the CSRF header.
func TestAuditDefectDojoSettingsAndRoleFormWithCSRFHeader(t *testing.T) {
	e := newLeakEnv(t)
	code, _, _ := e.post("dojocfg", "/defectdojo/settings", url.Values{"base_url": {"https://dojo.example"}, "token": {"x"}, "product_id": {"1"}, "engagement_id": {"1"}, "force": {"1"}})
	if code != http.StatusSeeOther && code != http.StatusForbidden {
		t.Errorf("POST /defectdojo/settings as scan.configure only = %d, want a redirect or 403", code)
	}

	withHeader := func(path string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "text/html")
		req.Header.Set(auth.CSRFHeader, e.csrf[auth.RoleAdmin])
		req.AddCookie(e.cookies[auth.RoleAdmin])
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}
	want := []auth.Permission{"export", "inventory.read"}
	if rec := withHeader("/roles/create", url.Values{"name": {"hdrrole"}, "perm": {"export", "inventory.read"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("create role with CSRF header = %d\n%.300s", rec.Code, rec.Body)
	}
	if r, _ := e.role(t, "hdrrole"); !slices.Equal(r.Permissions, want) {
		t.Errorf("role created with the CSRF token in the header has permissions %v, want %v", r.Permissions, want)
	}
	if rec := withHeader("/roles/nobody", url.Values{"perm": {"export", "inventory.read"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("update role with CSRF header = %d\n%.300s", rec.Code, rec.Body)
	}
	if r, _ := e.role(t, "nobody"); !slices.Equal(r.Permissions, want) {
		t.Errorf("role saved with the CSRF token in the header has permissions %v, want %v", r.Permissions, want)
	}
}

// AC7: every GET route answers 403 or a redirect unless the role holds what the route needs.
func TestAuditEveryGetRouteDeniesRolesWithoutItsPermissions(t *testing.T) {
	e := newLeakEnv(t)
	extra := map[string][]auth.Permission{
		"/signatures/hunts/{id}":                             {auth.PermInventoryRead},
		"/signatures/hunts/{id}/csv":                         {auth.PermInventoryRead, auth.PermExport},
		"/hosts/{address}/delete":                            {auth.PermInventoryRead},
		"/hosts/{address}/services/{port}/{protocol}/delete": {auth.PermInventoryRead},
	}
	roles := []string{auth.RoleAdmin, auth.RoleEditor, auth.RoleOperator, auth.RoleViewer, "nobody", "exporter", "sigonly"}
	values := map[string]string{"{address}": auditHost, "{name}": "app.css", "{username}": "viewer", "{port}": "22", "{protocol}": "tcp", "{$}": ""}
	for _, role := range roles {
		r, ok := e.role(t, role)
		if !ok {
			t.Fatalf("no role %s", role)
		}
		for _, rt := range e.r.Routes() {
			if rt.Method != http.MethodGet || rt.Access.IsPublic() {
				continue
			}
			need := slices.Clone(extra[rt.Path])
			if p, gated := rt.Access.Permission(); gated {
				need = append(need, p)
			}
			holds := true
			for _, p := range need {
				holds = holds && slices.Contains(r.Permissions, p)
			}
			if holds {
				continue
			}
			v := e.runID
			if strings.HasPrefix(rt.Path, "/signatures/hunts/") {
				v = e.huntID
			}
			target := strings.ReplaceAll(rt.Path, "{id}", v)
			for k, val := range values {
				target = strings.ReplaceAll(target, k, val)
			}
			code, _ := e.get(role, target)
			if code != http.StatusForbidden && (code < 300 || code > 399) {
				t.Errorf("GET %s as %s (needs %v) = %d, want 403 or a redirect", target, role, need, code)
			}
		}
	}
}
