package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/exchange/defectdojo"
	"asi/internal/inventory"
)

type fakeDojo struct {
	view       defectdojo.View
	configured []defectdojo.Config
	actors     []string
	exported   []string
	testErr    error
	exportErr  error
	forced     []string
	storedErr  error
}

func (f *fakeDojo) CheckStoredTests(context.Context) error { return f.storedErr }

func (f *fakeDojo) ForceExport(_ context.Context, a auth.Actor, run string) (defectdojo.Result, error) {
	f.forced = append(f.forced, a.Username+" "+run)
	f.view.FindingsTestID = 52
	return defectdojo.Result{Run: run, Hosts: 1, Services: 1, Findings: 0, NmapTestID: 41, FindingsTestID: 52,
		Recreated: []string{"the findings test 42 no longer existed in DefectDojo and was recreated as test 52"}}, nil
}

func (f *fakeDojo) View(context.Context) (defectdojo.View, error) { return f.view, nil }

func (f *fakeDojo) Configure(_ context.Context, a auth.Actor, c defectdojo.Config) error {
	if c.ProductID < 1 {
		return defectdojo.ErrInvalidConfig
	}
	f.configured = append(f.configured, c)
	f.actors = append(f.actors, a.Username)
	f.view = defectdojo.View{BaseURL: c.BaseURL, TokenSet: true, ProductID: c.ProductID, EngagementID: c.EngagementID}
	return nil
}

func (f *fakeDojo) TestConnection(context.Context) error { return f.testErr }

func (f *fakeDojo) Export(_ context.Context, a auth.Actor, run string) (defectdojo.Result, error) {
	if f.exportErr != nil {
		return defectdojo.Result{}, f.exportErr
	}
	f.exported = append(f.exported, a.Username+" "+run)
	return defectdojo.Result{Run: "r2", Hosts: 2, Services: 3, Findings: 7, NmapTestID: 41, FindingsTestID: 42}, nil
}

func newDojoRouter(t *testing.T) (*Router, *fakeAuth, *fakeDojo) {
	t.Helper()
	fa := newFakeAuth()
	fa.passwords["edith"] = "edith-password-1"
	fa.roles["edith"] = auth.Principal{Username: "edith", Role: "custom",
		Permissions: []auth.Permission{auth.PermInventoryRead, auth.PermInventoryEdit, auth.PermScanRun}}
	fd := &fakeDojo{view: defectdojo.View{BaseURL: "https://dojo.example", TokenSet: true, ProductID: 2, EngagementID: 3, NmapTestID: 41}}
	r, err := build(Deps{Auth: fa, DefectDojo: fd}, files, features)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return r, fa, fd
}

// REQ-DEFECTDOJO-001
func TestDefectDojoPageHidesToken(t *testing.T) {
	r, fa, _ := newDojoRouter(t)
	rec := do(r, http.MethodGet, "/defectdojo", nil, fa.session(t, "alice"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `value="https://dojo.example"`) || !strings.Contains(body, "A token is saved") ||
		!strings.Contains(body, `<a href="/defectdojo" aria-current="page">DefectDojo</a>`) || !strings.Contains(body, `action="/defectdojo/test"`) {
		t.Fatalf("GET /defectdojo = %d\n%s", rec.Code, body)
	}
	if strings.Contains(body, `name="token" value`) {
		t.Fatal("token field has a value")
	}
}

// REQ-DEFECTDOJO-006
func TestDefectDojoRequiresExportPermission(t *testing.T) {
	r, fa, fd := newDojoRouter(t)
	edith := fa.session(t, "edith")
	if rec := do(r, http.MethodGet, "/", nil, edith); strings.Contains(rec.Body.String(), "/defectdojo") {
		t.Fatal("nav shows DefectDojo without the export permission")
	}
	for _, path := range []string{"/defectdojo", "/defectdojo/settings", "/defectdojo/test", "/defectdojo/export"} {
		method := http.MethodPost
		if path == "/defectdojo" {
			method = http.MethodGet
		}
		if rec := do(r, method, path, url.Values{"csrf_token": {"csrf-edith"}, "run": {"r2"}}, edith); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s without export = %d, want 403", method, path, rec.Code)
		}
	}
	alice := fa.session(t, "alice")
	if rec := do(r, http.MethodPost, "/defectdojo/export", url.Values{"run": {"r2"}}, alice); rec.Code != http.StatusForbidden {
		t.Errorf("export without CSRF = %d, want 403", rec.Code)
	}
	if len(fd.exported) != 0 || len(fd.configured) != 0 {
		t.Fatalf("forbidden requests reached the service: %v %v", fd.exported, fd.configured)
	}
}

// REQ-DEFECTDOJO-006
func TestDefectDojoActions(t *testing.T) {
	r, fa, fd := newDojoRouter(t)
	alice := fa.session(t, "alice")
	form := url.Values{"csrf_token": {"csrf-alice"}, "base_url": {"https://dojo2.example"}, "token": {"posted-secret"},
		"product_id": {"4"}, "engagement_id": {"5"}}
	rec := do(r, http.MethodPost, "/defectdojo/settings", form, alice)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Saved.") || strings.Contains(body, "posted-secret") {
		t.Fatalf("save = %d\n%s", rec.Code, body)
	}
	if len(fd.configured) != 1 || fd.configured[0] != (defectdojo.Config{BaseURL: "https://dojo2.example", Token: "posted-secret", ProductID: 4, EngagementID: 5}) || fd.actors[0] != "alice" {
		t.Fatalf("configured = %+v %v", fd.configured, fd.actors)
	}
	form.Set("product_id", "abc")
	if rec := do(r, http.MethodPost, "/defectdojo/settings", form, alice); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "notice error") {
		t.Fatalf("invalid save = %d", rec.Code)
	}

	csrf := url.Values{"csrf_token": {"csrf-alice"}}
	if rec := do(r, http.MethodPost, "/defectdojo/test", csrf, alice); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Connection works") {
		t.Fatalf("test = %d\n%s", rec.Code, rec.Body.String())
	}
	fd.testErr = &defectdojo.APIError{Method: "GET", Path: "/api/v2/engagements/5/", Status: 401}
	rec = do(r, http.MethodPost, "/defectdojo/test", csrf, alice)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "401 Unauthorized") {
		t.Fatalf("failed test = %d\n%s", rec.Code, rec.Body.String())
	}

	rec = do(r, http.MethodPost, "/defectdojo/export", url.Values{"csrf_token": {"csrf-alice"}, "run": {" r2 "}}, alice)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Exported run r2: 2 hosts and 3 services to test 41, 7 findings to test 42.") {
		t.Fatalf("export = %d\n%s", rec.Code, rec.Body.String())
	}
	if len(fd.exported) != 1 || fd.exported[0] != "alice r2" {
		t.Fatalf("exported = %v", fd.exported)
	}
	fd.exportErr = inventory.ErrUnknownRun
	rec = do(r, http.MethodPost, "/defectdojo/export", url.Values{"csrf_token": {"csrf-alice"}, "run": {"nope"}}, alice)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "Run &#34;nope&#34; does not exist.") {
		t.Fatalf("unknown run = %d\n%s", rec.Code, rec.Body.String())
	}
	fd.exportErr = defectdojo.ErrNotConfigured
	if rec := do(r, http.MethodPost, "/defectdojo/export", url.Values{"csrf_token": {"csrf-alice"}}, alice); rec.Code != http.StatusConflict {
		t.Fatalf("unconfigured export = %d", rec.Code)
	}
}

// REQ-DEFECTDOJO-006
func TestDefectDojoSettingsNeedScanConfigure(t *testing.T) {
	r, fa, fd := newDojoRouter(t)
	fa.passwords["otto"] = "otto-password-1"
	fa.roles["otto"] = auth.Principal{Username: "otto", Role: auth.RoleOperator,
		Permissions: []auth.Permission{auth.PermInventoryRead, auth.PermInventoryEdit, auth.PermExport}}
	otto := fa.session(t, "otto")
	rec := do(r, http.MethodGet, "/defectdojo", nil, otto)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || strings.Contains(body, `action="/defectdojo/settings"`) || !strings.Contains(body, "https://dojo.example") {
		t.Fatalf("GET as operator = %d\n%s", rec.Code, body)
	}
	form := url.Values{"csrf_token": {"csrf-otto"}, "base_url": {"https://attacker.example"}, "product_id": {"2"}, "engagement_id": {"3"}}
	if rec := do(r, http.MethodPost, "/defectdojo/settings", form, otto); rec.Code != http.StatusForbidden {
		t.Fatalf("settings as operator = %d, want 403", rec.Code)
	}
	if len(fd.configured) != 0 {
		t.Fatalf("operator changed the configuration: %+v", fd.configured)
	}
	if rec := do(r, http.MethodPost, "/defectdojo/export", url.Values{"csrf_token": {"csrf-otto"}, "run": {"r2"}}, otto); rec.Code != http.StatusOK {
		t.Fatalf("export as operator = %d", rec.Code)
	}
}

// REQ-DEFECTDOJO-006 REQ-DEFECTDOJO-009
func TestDefectDojoPageGuidesAndConfirms(t *testing.T) {
	r, fa, fd := newDojoRouter(t)
	alice := fa.session(t, "alice")
	body := do(r, http.MethodGet, "/defectdojo", nil, alice).Body.String()
	for _, want := range []string{"2 in /product/2", "3 in /engagement/3", `name="force" value="1"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page does not contain %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "/engagement/3\"") || regexp.MustCompile(`style\s*=`).MatchString(body) {
		t.Fatalf("page links to DefectDojo before an export or uses inline styles\n%s", body)
	}

	fd.exportErr = fmt.Errorf("%w: run r1 is older than run r2, the last one exported to this engagement", defectdojo.ErrOlderRun)
	rec := do(r, http.MethodPost, "/defectdojo/export", url.Values{"csrf_token": {"csrf-alice"}, "run": {"r1"}}, alice)
	body = rec.Body.String()
	if rec.Code != http.StatusConflict || !strings.Contains(body, "Run r1 is older than run r2") ||
		!strings.Contains(body, `<input type="hidden" name="force" value="1">`) || !strings.Contains(body, "Export run r1 anyway") {
		t.Fatalf("older run = %d\n%s", rec.Code, body)
	}
	if len(fd.forced) != 0 {
		t.Fatal("older run exported without confirmation")
	}
	rec = do(r, http.MethodPost, "/defectdojo/export", url.Values{"csrf_token": {"csrf-alice"}, "run": {"r1"}, "force": {"1"}}, alice)
	body = rec.Body.String()
	if rec.Code != http.StatusOK || len(fd.forced) != 1 || fd.forced[0] != "alice r1" ||
		!strings.Contains(body, "The findings test 42 no longer existed in DefectDojo and was recreated as test 52.") {
		t.Fatalf("confirmed export = %d %v\n%s", rec.Code, fd.forced, body)
	}
	for _, link := range []string{`href="https://dojo.example/engagement/3"`, `href="https://dojo.example/test/41"`, `href="https://dojo.example/test/52"`} {
		if !strings.Contains(body, link) {
			t.Fatalf("export result does not link %s\n%s", link, body)
		}
	}

	form := url.Values{"csrf_token": {"csrf-alice"}, "base_url": {"https://dojo.example"}, "product_id": {"2"}, "engagement_id": {"3"}, "force": {"1"}}
	if rec := do(r, http.MethodPost, "/defectdojo/settings", form, alice); rec.Code != http.StatusOK || len(fd.configured) != 1 || !fd.configured[0].Force {
		t.Fatalf("forced save = %d %+v", rec.Code, fd.configured)
	}
	fd.storedErr = fmt.Errorf("%w: %w", defectdojo.ErrTestsMissing, errors.New("the connection works, but the stored nmap test 41 no longer exist in DefectDojo"))
	rec = do(r, http.MethodPost, "/defectdojo/test", url.Values{"csrf_token": {"csrf-alice"}}, alice)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "stored nmap test 41") {
		t.Fatalf("missing test = %d\n%s", rec.Code, rec.Body.String())
	}
	msg, status := dojoError(fmt.Errorf("%w: %w", defectdojo.ErrNotSaved, &defectdojo.APIError{Method: "GET", Path: "/api/v2/engagements/3/", Status: 403}))
	if status != http.StatusBadGateway || !strings.HasPrefix(msg, "Not saved: the connection test failed") || !strings.Contains(msg, "token was rejected") {
		t.Fatalf("not saved = %d %q", status, msg)
	}
}

// REQ-WEB-054
func TestDefectDojoSettingsWithoutExportRedirect(t *testing.T) {
	r, fa, fd := newDojoRouter(t)
	fa.passwords["cfg"] = "cfg-password-1"
	fa.roles["cfg"] = auth.Principal{Username: "cfg", Role: "custom", Permissions: []auth.Permission{auth.PermScanConfigure}}
	cfg := fa.session(t, "cfg")
	form := url.Values{"csrf_token": {"csrf-cfg"}, "base_url": {"https://dojo3.example"}, "token": {"cfg-secret"},
		"product_id": {"6"}, "engagement_id": {"7"}, "force": {"1"}}
	rec := do(r, http.MethodPost, "/defectdojo/settings", form, cfg)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/defectdojo" {
		t.Fatalf("save without export = %d Location %q, want 303 to /defectdojo\n%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if len(fd.configured) != 1 || fd.configured[0].BaseURL != "https://dojo3.example" || fd.configured[0].Token != "cfg-secret" || fd.actors[0] != "cfg" {
		t.Fatalf("configured = %+v %v", fd.configured, fd.actors)
	}
	form.Set("product_id", "abc")
	rec = do(r, http.MethodPost, "/defectdojo/settings", form, cfg)
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || strings.Contains(body, `action="/defectdojo/test"`) || strings.Contains(body, "https://dojo3.example") ||
		strings.Contains(body, "cfg-secret") {
		t.Fatalf("rejected save without export = %d, want 400 without the DefectDojo page\n%s", rec.Code, body)
	}
	if regexp.MustCompile(`style\s*=`).MatchString(body) {
		t.Fatal("error page uses inline styles")
	}
	if rec := do(r, http.MethodGet, "/defectdojo", nil, cfg); rec.Code != http.StatusForbidden {
		t.Fatalf("GET /defectdojo without export = %d, want 403", rec.Code)
	}
	alice := fa.session(t, "alice")
	form = url.Values{"csrf_token": {"csrf-alice"}, "base_url": {"https://dojo4.example"}, "token": {"alice-secret"}, "product_id": {"8"}, "engagement_id": {"9"}}
	rec = do(r, http.MethodPost, "/defectdojo/settings", form, alice)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Saved.") || strings.Contains(rec.Body.String(), "alice-secret") {
		t.Fatalf("admin save = %d\n%s", rec.Code, rec.Body.String())
	}
}
