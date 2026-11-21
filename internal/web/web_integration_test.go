//go:build integration

package web

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func get(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// REQ-WEB-003 REQ-WEB-009
func TestLoginDashboardLogoutWithRealAuth(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	svc := auth.NewService(st, auth.Config{})
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, "olga", "olga-password-123", auth.RoleOperator); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	h, err := New(Deps{Store: st, Auth: svc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	resp, body := get(t, c, srv.URL+"/healthz")
	if resp.StatusCode != http.StatusOK || body != "ok\n" {
		t.Fatalf("/healthz = %d %q", resp.StatusCode, body)
	}
	resp, body = get(t, c, srv.URL+"/")
	if resp.Request.URL.Path != "/login" || !strings.Contains(body, "Sign in") {
		t.Fatalf("anonymous / ended at %s", resp.Request.URL)
	}
	m := csrfInput.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("login form has no CSRF token")
	}
	resp, err = c.PostForm(srv.URL+"/login", url.Values{"username": {"olga"}, "password": {"olga-password-123"}, "csrf_token": {m[1]}})
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dash := string(b)
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/" ||
		!strings.Contains(dash, `<strong class="username">olga</strong>`) || !strings.Contains(dash, `<strong class="role">operator</strong>`) {
		t.Fatalf("after login: %d at %s:\n%s", resp.StatusCode, resp.Request.URL, dash)
	}
	checkSecurityHeaders(t, "dashboard", resp.Header)

	token := csrfInput.FindStringSubmatch(dash)
	if token == nil {
		t.Fatal("dashboard has no CSRF field")
	}
	resp, err = c.PostForm(srv.URL+"/logout", url.Values{"csrf_token": {token[1]}})
	if err != nil {
		t.Fatalf("POST /logout: %v", err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path != "/login" {
		t.Fatalf("logout ended at %s", resp.Request.URL)
	}
	resp, _ = get(t, c, srv.URL+"/")
	if resp.Request.URL.Path != "/login" {
		t.Fatalf("/ after logout ended at %s, want /login", resp.Request.URL)
	}
}

// REQ-SIGNATURES-001 REQ-SIGNATURES-002 REQ-SIGNATURES-003 REQ-SIGNATURES-004 REQ-SIGNATURES-005
func TestSignatureLifecycleWithRealStore(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	keys, err := store.NewKeyring(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(st, auth.Config{})
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, "eddie", "eddie-password-123", auth.RoleEditor); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	sess, err := svc.Login(ctx, "eddie", "eddie-password-123", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	cookie := &http.Cookie{Name: auth.SessionCookieName, Value: sess.Token}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte("- {id: dir-sig, name: D, kind: custom, confidence: 1, match: {all: [{type: status, value: 200}]}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	contacted := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacted = true }))
	t.Cleanup(target.Close)
	inv := inventory.New(st, keys)
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "r1", Settings: inventory.RunSettings{Targets: []string{"10.0.0.5"}, Ports: []int{80}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.5"}, Hosts: []inventory.HostResult{{
		Address: "10.0.0.5", Services: []inventory.ServiceResult{{Port: 80, Protocol: "tcp", State: "open", Service: "http",
			HTTP: &probe.HTTP{Scheme: "http", URL: target.URL + "/", StatusCode: 200, Title: "Grafana",
				Headers: map[string]string{"server": "nginx/1.27.5"}, Cookies: []probe.Cookie{{Name: "grafana_session"}}}}},
	}}}); err != nil {
		t.Fatalf("RecordGroup: %v", err)
	}

	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, SignaturesDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	post := func(path string, v url.Values) *httptest.ResponseRecorder {
		t.Helper()
		v.Set(auth.CSRFFormField, sess.CSRFToken)
		return do(h, http.MethodPost, path, v, cookie)
	}
	want := func(what string, rec *httptest.ResponseRecorder, status int, text string) {
		t.Helper()
		if rec.Code != status || !strings.Contains(rec.Body.String()+rec.Header().Get("Location"), text) {
			t.Fatalf("%s = %d (Location %q), want %d containing %q:\n%s", what, rec.Code, rec.Header().Get("Location"), status, text, rec.Body)
		}
	}
	lib := detect.NewLibrary(st, "")
	enabledIDs := func() []string {
		t.Helper()
		sigs, err := lib.Enabled(ctx)
		if err != nil {
			t.Fatalf("Enabled: %v", err)
		}
		var ids []string
		for _, s := range sigs {
			ids = append(ids, s.ID)
		}
		return ids
	}
	before := 0
	if err := st.Pool.QueryRow(ctx, `SELECT coalesce(max(id), 0) FROM audit_log`).Scan(&before); err != nil {
		t.Fatal(err)
	}

	grafana := "id: grafana\nname: Grafana\nkind: technology\ncategory: monitoring\nconfidence: 90\nmatch:\n  all:\n    - {type: title_regex, value: Grafana}\n  any:\n    - {type: cookie, name: '^grafana_'}\nversion: {type: header, name: Server, value: 'nginx/([0-9.]+)', group: 1}\n"
	want("list empty", do(h, http.MethodGet, "/signatures", nil, cookie), http.StatusOK, "No signatures yet.")
	want("new form", do(h, http.MethodGet, "/signatures/new", nil, cookie), http.StatusOK, `name="source"`)
	want("create", post("/signatures", url.Values{"source": {grafana}, "enabled": {"1"}}), http.StatusSeeOther, "/signatures?done=created&id=grafana")
	want("list", do(h, http.MethodGet, "/signatures?done=created&id=grafana", nil, cookie), http.StatusOK, "Signature grafana created.")
	want("unsafe method", post("/signatures", url.Values{"source": {strings.Replace(grafana, "match:", "request: {method: POST, path: /login}\nmatch:", 1)}}),
		http.StatusUnprocessableEntity, "Rule violated: "+detect.RuleMethod)
	want("query string", post("/signatures", url.Values{"source": {strings.Replace(grafana, "match:", "request: {path: '/x?a=1'}\nmatch:", 1)}}),
		http.StatusUnprocessableEntity, "Rule violated: "+detect.RulePath)
	want("stored id clash", post("/signatures", url.Values{"source": {grafana}}), http.StatusUnprocessableEntity, "Rule violated: "+detect.RuleDuplicateID)
	want("directory id clash", post("/signatures", url.Values{"source": {strings.Replace(grafana, "id: grafana", "id: dir-sig", 1)}}),
		http.StatusUnprocessableEntity, "Rule violated: "+detect.RuleDuplicateID)
	if ids := enabledIDs(); len(ids) != 1 || ids[0] != "grafana" {
		t.Fatalf("enabled after create = %v", ids)
	}

	want("edit form", do(h, http.MethodGet, "/signatures/grafana", nil, cookie), http.StatusOK, "category: monitoring")
	want("unknown", do(h, http.MethodGet, "/signatures/nope", nil, cookie), http.StatusNotFound, "does not exist")
	want("update", post("/signatures/grafana", url.Values{"source": {strings.Replace(grafana, "name: Grafana", "name: Grafana UI", 1)}}), http.StatusSeeOther, "done=saved")
	if s, err := lib.Get(ctx, "grafana"); err != nil || s.Name != "Grafana UI" || s.Enabled {
		t.Fatalf("after update = %+v, %v", s, err)
	}
	want("rename rejected", post("/signatures/grafana", url.Values{"source": {strings.Replace(grafana, "id: grafana", "id: other", 1)}}), http.StatusUnprocessableEntity, "cannot change")
	want("enable", post("/signatures/grafana/enable", url.Values{}), http.StatusSeeOther, "done=enabled")
	want("disable", post("/signatures/grafana/disable", url.Values{}), http.StatusSeeOther, "done=disabled")
	if ids := enabledIDs(); len(ids) != 0 {
		t.Fatalf("enabled after disable = %v", ids)
	}
	want("list disabled", do(h, http.MethodGet, "/signatures", nil, cookie), http.StatusOK, `<span class="status inactive">Disabled</span>`)
	want("enable again", post("/signatures/grafana/enable", url.Values{}), http.StatusSeeOther, "done=enabled")

	draft := strings.Replace(grafana, "Grafana}", "Grafana}\n    - {type: status, value: 200}", 1)
	test := post("/signatures/test", url.Values{"source": {draft}, "id": {"grafana"}, "address": {"10.0.0.5"}, "port": {"80"}, "protocol": {"tcp"}})
	want("test match", test, http.StatusOK, "Matches 10.0.0.5 80/tcp, version 1.27.5.")
	want("test run", test, http.StatusOK, "<dd>r1</dd>")
	want("test keeps the draft", test, http.StatusOK, "value: 200}")
	want("test no match", post("/signatures/test", url.Values{"source": {strings.Replace(grafana, "value: Grafana", "value: Kibana", 1)}, "address": {"10.0.0.5"}, "port": {"80"}, "protocol": {"tcp"}}),
		http.StatusOK, "No match on 10.0.0.5 80/tcp.")
	want("test unknown service", post("/signatures/test", url.Values{"source": {grafana}, "address": {"10.0.0.6"}, "port": {"80"}, "protocol": {"tcp"}}),
		http.StatusUnprocessableEntity, "No stored observation of 10.0.0.6 80/tcp.")
	want("test invalid draft", post("/signatures/test", url.Values{"source": {strings.Replace(grafana, "match:", "request: {method: PUT}\nmatch:", 1)}, "address": {"10.0.0.5"}, "port": {"80"}, "protocol": {"tcp"}}),
		http.StatusUnprocessableEntity, "Rule violated: "+detect.RuleMethod)
	if contacted {
		t.Fatal("the test action sent a request to the service")
	}
	if s, _ := lib.Get(ctx, "grafana"); strings.Contains(s.Source, "value: 200") {
		t.Fatal("the test action saved the draft")
	}

	exp := do(h, http.MethodGet, "/signatures/export", nil, cookie)
	if exp.Code != http.StatusOK || !strings.HasPrefix(exp.Header().Get("Content-Type"), "application/yaml") {
		t.Fatalf("export = %d %s", exp.Code, exp.Header().Get("Content-Type"))
	}
	exported, err := detect.Parse(exp.Body.Bytes())
	if err != nil || len(exported) != 1 || exported[0].ID != "grafana" || exported[0].Name != "Grafana UI" || exported[0].Version == nil {
		t.Fatalf("exported %q: %+v, %v", exp.Body, exported, err)
	}
	file := exp.Body.String() + "- {id: staging-banner, name: Staging, kind: staging, confidence: 60, match: {any: [{type: title_regex, value: '(?i)staging'}]}}\n"
	want("import", post("/signatures/import", url.Values{"yaml": {file}}), http.StatusSeeOther, "done=imported&id=2")
	want("import unsafe", post("/signatures/import", url.Values{"yaml": {"- {id: x, name: X, kind: custom, confidence: 1, request: {path: /x, body: a}, match: {all: [{type: status, value: 200}]}}\n"}}),
		http.StatusUnprocessableEntity, "Rule violated: "+detect.RuleBody)
	want("import clash", post("/signatures/import", url.Values{"yaml": {"- {id: dir-sig, name: X, kind: custom, confidence: 1, match: {all: [{type: status, value: 200}]}}\n"}}),
		http.StatusUnprocessableEntity, "Rule violated: "+detect.RuleDuplicateID)
	want("import not yaml", post("/signatures/import", url.Values{"yaml": {"id: ["}}), http.StatusUnprocessableEntity, "Rule violated: "+detect.RuleSchema)
	if ids := enabledIDs(); strings.Join(ids, ",") != "grafana,staging-banner" {
		t.Fatalf("enabled after import = %v", ids)
	}
	want("delete", post("/signatures/staging-banner/delete", url.Values{}), http.StatusSeeOther, "done=deleted")
	want("deleted", do(h, http.MethodGet, "/signatures/staging-banner", nil, cookie), http.StatusNotFound, "does not exist")
	want("delete unknown", post("/signatures/staging-banner/delete", url.Values{}), http.StatusNotFound, "does not exist")

	rows, err := st.Pool.Query(ctx, `SELECT actor || ' ' || action || ' ' || target FROM audit_log WHERE id > $1 ORDER BY id`, before)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	wantAudit := []string{
		"eddie signature.create grafana", "eddie signature.update grafana", "eddie signature.enable grafana",
		"eddie signature.disable grafana", "eddie signature.enable grafana", "eddie signature.import grafana",
		"eddie signature.import staging-banner", "eddie signature.delete staging-banner",
	}
	if strings.Join(got, "\n") != strings.Join(wantAudit, "\n") {
		t.Fatalf("audit log:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantAudit, "\n"))
	}
}
