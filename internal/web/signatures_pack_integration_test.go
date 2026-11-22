//go:build integration

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

type packSession struct {
	cookie *http.Cookie
	csrf   string
}

func packLogin(t *testing.T, svc *auth.Service, name, role string) packSession {
	t.Helper()
	ctx := context.Background()
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, name, name+"-password-123", role); err != nil {
		t.Fatalf("CreateUser %s: %v", name, err)
	}
	sess, err := svc.Login(ctx, name, name+"-password-123", "")
	if err != nil {
		t.Fatalf("Login %s: %v", name, err)
	}
	return packSession{cookie: &http.Cookie{Name: auth.SessionCookieName, Value: sess.Token}, csrf: sess.CSRFToken}
}

func (s packSession) post(h http.Handler, path string, v url.Values) *httptest.ResponseRecorder {
	v.Set(auth.CSRFFormField, s.csrf)
	return do(h, http.MethodPost, path, v, s.cookie)
}

func TestPackSignaturesInUI(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pack, err := detect.Pack()
	if err != nil || len(pack) == 0 {
		t.Fatalf("Pack = %d signatures, %v", len(pack), err)
	}
	id := pack[0].ID
	svc := auth.NewService(st, auth.Config{})
	editor := packLogin(t, svc, "eddie", auth.RoleEditor)
	viewer := packLogin(t, svc, "vera", auth.RoleViewer)
	operator := packLogin(t, svc, "olga", auth.RoleOperator)
	keys, err := store.NewKeyring(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := func(what string, rec *httptest.ResponseRecorder, status int, text string) {
		t.Helper()
		if rec.Code != status || !strings.Contains(rec.Body.String()+rec.Header().Get("Location"), text) {
			t.Fatalf("%s = %d (Location %q), want %d containing %q:\n%s", what, rec.Code, rec.Header().Get("Location"), status, text, rec.Body)
		}
	}
	lib := detect.NewLibrary(st, keys, "")
	isEnabled := func() bool {
		t.Helper()
		sigs, err := lib.Enabled(ctx)
		if err != nil {
			t.Fatalf("Enabled: %v", err)
		}
		for _, s := range sigs {
			if s.ID == id {
				return true
			}
		}
		return false
	}

	list := do(h, http.MethodGet, "/signatures", nil, editor.cookie)
	want("list", list, http.StatusOK, "Built-in signatures")
	for _, s := range pack {
		row := `<a class="addr" href="/signatures/` + s.ID + `">` + s.ID + `</a> <span class="tag">Built-in</span>`
		if !strings.Contains(list.Body.String(), row) {
			t.Fatalf("list has no built-in row for %s", s.ID)
		}
	}
	want("list disable button", list, http.StatusOK, `action="/signatures/`+id+`/disable"`)
	want("list empty stored", list, http.StatusOK, "No signatures yet.")
	view := do(h, http.MethodGet, "/signatures/"+id, nil, editor.cookie)
	want("view", view, http.StatusOK, "readonly>")
	want("view source", view, http.StatusOK, "id: "+id)
	if strings.Contains(view.Body.String(), "Save changes") || strings.Contains(view.Body.String(), "/delete") {
		t.Fatalf("built-in signature page offers save or delete:\n%s", view.Body)
	}

	for _, s := range []packSession{viewer, operator} {
		for _, p := range []string{"/signatures/" + id + "/disable", "/signatures/" + id + "/enable", "/signatures/" + id, "/signatures/" + id + "/delete"} {
			want("forbidden "+p, s.post(h, p, url.Values{"source": {"id: " + id}}), http.StatusForbidden, "")
		}
		want("forbidden list", do(h, http.MethodGet, "/signatures", nil, s.cookie), http.StatusForbidden, "")
	}
	if !isEnabled() {
		t.Fatal("pack signature disabled by a forbidden request")
	}

	want("disable", editor.post(h, "/signatures/"+id+"/disable", url.Values{}), http.StatusSeeOther, "/signatures?done=disabled&id="+id)
	if isEnabled() {
		t.Fatal("pack signature still enabled after disable")
	}
	restarted, err := New(Deps{Store: st, Auth: svc})
	if err != nil {
		t.Fatalf("New after restart: %v", err)
	}
	want("disabled after restart", do(restarted, http.MethodGet, "/signatures/"+id, nil, editor.cookie), http.StatusOK, "Disabled: scans do not use this signature.")
	want("list after restart", do(restarted, http.MethodGet, "/signatures", nil, editor.cookie), http.StatusOK, `action="/signatures/`+id+`/enable"`)
	if isEnabled() {
		t.Fatal("pack signature enabled again after restart")
	}

	src := "id: " + id + "\nname: Mine\nkind: custom\nconfidence: 1\nmatch: {all: [{type: status, value: 200}]}\n"
	want("save", editor.post(h, "/signatures/"+id, url.Values{"source": {src}, "enabled": {"1"}}), http.StatusUnprocessableEntity, "Rule violated: ")
	want("delete", editor.post(h, "/signatures/"+id+"/delete", url.Values{}), http.StatusUnprocessableEntity, "Rule violated: ")
	want("create", editor.post(h, "/signatures", url.Values{"source": {src}, "enabled": {"1"}}), http.StatusUnprocessableEntity, "Rule violated: "+detect.RuleDuplicateID)
	want("import", editor.post(h, "/signatures/import", url.Values{"yaml": {"- {id: " + id + ", name: Mine, kind: custom, confidence: 1, match: {all: [{type: status, value: 200}]}}\n"}}),
		http.StatusUnprocessableEntity, "Rule violated: "+detect.RuleDuplicateID)
	if isEnabled() {
		t.Fatal("a rejected save enabled the pack signature")
	}
	var stored int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM signatures`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatalf("%d signatures stored after rejected writes", stored)
	}

	want("enable", editor.post(h, "/signatures/"+id+"/enable", url.Values{}), http.StatusSeeOther, "/signatures?done=enabled&id="+id)
	if !isEnabled() {
		t.Fatal("pack signature not enabled after enable")
	}
	exp := do(h, http.MethodGet, "/signatures/export", nil, editor.cookie)
	if exp.Code != http.StatusOK || strings.Contains(exp.Body.String(), detect.PackIDPrefix) {
		t.Fatalf("export = %d, contains pack signatures:\n%s", exp.Code, exp.Body)
	}

	rows, err := st.Pool.Query(ctx, `SELECT actor || ' ' || action || ' ' || target FROM audit_log WHERE action LIKE 'signature.%' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	wantAudit := "eddie signature.disable " + id + "\neddie signature.enable " + id
	if strings.Join(got, "\n") != wantAudit {
		t.Fatalf("audit log:\n%s\nwant:\n%s", strings.Join(got, "\n"), wantAudit)
	}
}

func (e *leakEnv) huntFindings(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.st.Pool.QueryRow(context.Background(), `SELECT count(*) FROM findings WHERE signature_id = 'auditportal'`).Scan(&n); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	return n
}

// REQ-SIGNATURES-026
func TestSignatureRoutesByInventoryPermissions(t *testing.T) {
	e := newLeakEnv(t)
	for _, path := range []string{"/signatures", "/signatures/new", "/signatures/export"} {
		if code, body := e.get("sigonly", path); code != http.StatusOK || len(e.leaks(body)) > 0 {
			t.Errorf("GET %s as signature.manage only = %d (leaks %q), want 200", path, code, e.leaks(body))
		}
	}
	if _, body := e.get("sigonly", "/signatures/new"); strings.Contains(body, `formaction="/signatures/hunt"`) || strings.Contains(body, `formaction="/signatures/test"`) {
		t.Error("signature form offers test and hunt to a role without inventory.read")
	}
	if _, body := e.get(auth.RoleEditor, "/signatures/new"); !strings.Contains(body, `formaction="/signatures/hunt"`) || !strings.Contains(body, `formaction="/signatures/test"`) {
		t.Error("signature form does not offer test and hunt to a role with inventory.read")
	}
	src := "id: ctl-sig\nname: Control\nkind: technology\nconfidence: 50\nmatch:\n  all:\n    - {type: title_regex, value: 'Nothing'}\n"
	for _, step := range []struct {
		path string
		form url.Values
	}{
		{"/signatures", url.Values{"source": {src}, "enabled": {"1"}}},
		{"/signatures/ctl-sig", url.Values{"source": {src}}},
		{"/signatures/ctl-sig/enable", url.Values{}},
		{"/signatures/ctl-sig/disable", url.Values{}},
		{"/signatures/ctl-sig/delete", url.Values{}},
	} {
		if code, loc, body := e.post("sigonly", step.path, step.form); code != http.StatusSeeOther || !strings.HasPrefix(loc, "/signatures?done=") {
			t.Errorf("POST %s as signature.manage only = %d %q\n%.300s", step.path, code, loc, body)
		}
	}

	hunt := "/signatures/hunts/" + e.huntID
	code, body := e.get("sigreader", hunt)
	if code != http.StatusOK || !strings.Contains(body, auditHost) || strings.Contains(body, hunt+"/csv") || strings.Contains(body, `name="record"`) {
		t.Errorf("hunt page with read but without export and edit = %d, want results without CSV and record\n%.400s", code, body)
	}
	if code, _, _ := e.post("sigreader", hunt+"/save", url.Values{"record": {"1"}}); code != http.StatusForbidden {
		t.Errorf("save with record without inventory.edit = %d, want 403", code)
	}
	if n := e.huntFindings(t); n != 0 {
		t.Fatalf("%d findings recorded by a role without inventory.edit", n)
	}

	code, body = e.get(auth.RoleAdmin, hunt)
	if code != http.StatusOK || !strings.Contains(body, hunt+"/csv") || !strings.Contains(body, `name="record"`) {
		t.Errorf("hunt page as admin = %d, want the CSV link and the record option", code)
	}
	if code, body := e.get(auth.RoleAdmin, hunt+"/csv"); code != http.StatusOK || !strings.Contains(body, auditHost+",80,tcp") {
		t.Errorf("hunt CSV as admin = %d\n%.300s", code, body)
	}
	code, loc, _ := e.post(auth.RoleAdmin, hunt+"/save", url.Values{"record": {"1"}})
	if code != http.StatusSeeOther || !strings.Contains(loc, "recorded=1") {
		t.Errorf("save with record as admin = %d %q, want 303 with one recorded finding", code, loc)
	}
	if n := e.huntFindings(t); n != 1 {
		t.Errorf("findings after the admin recorded = %d, want 1", n)
	}
}
