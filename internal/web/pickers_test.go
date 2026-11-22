package web

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/exchange/defectdojo"
	"asi/internal/inventory"
)

var inlineStyle = regexp.MustCompile(`style\s*=`)

func (f *fakeDojo) Choices(context.Context, int) (defectdojo.Choices, error) {
	return defectdojo.Choices{}, errors.New("defectdojo GET /api/v2/products/: 404 Not Found")
}

type listingDojo struct {
	*fakeDojo
	asked []int
}

func (l *listingDojo) Choices(_ context.Context, productID int) (defectdojo.Choices, error) {
	l.asked = append(l.asked, productID)
	ch := defectdojo.Choices{Products: []defectdojo.Choice{{ID: 2, Name: "AGH network"}, {ID: 7, Name: "Web"}}}
	switch productID {
	case 0, 2:
		ch.Engagements = []defectdojo.Choice{{ID: 3, Name: "Weekly scan"}}
	case 7:
		ch.Engagements = []defectdojo.Choice{{ID: 11, Name: "Web review"}, {ID: 12, Name: "Pentest"}}
	}
	return ch, nil
}

func newListingDojoRouter(t *testing.T) (*Router, *fakeAuth, *listingDojo) {
	t.Helper()
	fa := newFakeAuth()
	fa.passwords["otto"] = "otto-password-1"
	fa.roles["otto"] = auth.Principal{Username: "otto", Role: auth.RoleOperator,
		Permissions: []auth.Permission{auth.PermInventoryRead, auth.PermExport}}
	ld := &listingDojo{fakeDojo: &fakeDojo{view: defectdojo.View{BaseURL: "https://dojo.example", TokenSet: true, ProductID: 2, EngagementID: 3}}}
	r, err := build(Deps{Auth: fa, DefectDojo: ld, Inventory: sampleInventory()}, files, features)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return r, fa, ld
}

// AC1: the export page picks the run from a list, newest first, Latest by default.
func TestExportPageRunSelect(t *testing.T) {
	r, _ := newTestRouter(t)
	runs := sampleInventory().runs
	render := func(p exportPage) string {
		rec := httptest.NewRecorder()
		r.Render(rec, httptest.NewRequest(http.MethodGet, "/export", nil), http.StatusOK, "export.html", View{Data: p})
		return rec.Body.String()
	}
	body := render(exportPage{Runs: runs})
	want := `<select name="run"><option value="">Latest</option><option value="r3">r3</option><option value="r2">r2</option><option value="r1">r1</option></select>`
	if !strings.Contains(body, want) || strings.Contains(body, `<input type="text" name="run"`) || strings.Contains(body, " selected>r") {
		t.Fatalf("export page lacks %s\n%s", want, body)
	}
	if body := render(exportPage{Runs: runs, Run: "r2"}); !strings.Contains(body, `<option value="r2" selected>r2</option>`) {
		t.Fatalf("export page does not keep run r2 selected\n%s", body)
	}
}

// AC2: Product and Engagement are selects filled from DefectDojo, Run a select of completed runs.
func TestDefectDojoPicksProductEngagementAndRun(t *testing.T) {
	r, fa, ld := newListingDojoRouter(t)
	alice := fa.session(t, "alice")
	rec := do(r, http.MethodGet, "/defectdojo", nil, alice)
	body := rec.Body.String()
	for _, want := range []string{
		`<option value="2" selected>AGH network (id 2)</option>`, `<option value="7">Web (id 7)</option>`,
		`<select name="engagement_id" required>`, `<option value="3" selected>Weekly scan (id 3)</option>`,
		`hx-get="/defectdojo" hx-include="this" hx-trigger="change" hx-target="#dojo-engagement"`,
		"2 in /product/2", "3 in /engagement/3",
		`<select name="run"><option value="">Latest</option><option value="r2">r2</option><option value="r1">r1</option></select>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if rec.Code != http.StatusOK || strings.Contains(body, `type="number"`) || strings.Contains(body, `value="r3"`) || inlineStyle.MatchString(body) {
		t.Fatalf("GET /defectdojo = %d\n%s", rec.Code, body)
	}
	if len(ld.asked) != 1 || ld.asked[0] != 2 {
		t.Fatalf("lists asked for products %v, want the saved product 2", ld.asked)
	}

	rec = do(r, http.MethodGet, "/defectdojo?product_id=7", nil, alice)
	body = rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `<option value="7" selected>Web (id 7)</option>`) ||
		!strings.Contains(body, `<label class="field" id="dojo-engagement"><span>Engagement</span><select name="engagement_id" required><option value="">Choose an engagement</option><option value="11">Web review (id 11)</option><option value="12">Pentest (id 12)</option></select>`) {
		t.Fatalf("GET /defectdojo?product_id=7 = %d\n%s", rec.Code, body)
	}
	if ld.asked[len(ld.asked)-1] != 7 {
		t.Fatalf("engagements asked for %v, want product 7", ld.asked)
	}

	form := url.Values{"csrf_token": {"csrf-alice"}, "base_url": {"https://dojo.example"}, "token": {"posted-secret"},
		"product_id": {"7"}, "engagement_id": {"12"}}
	rec = do(r, http.MethodPost, "/defectdojo/settings", form, alice)
	body = rec.Body.String()
	if rec.Code != http.StatusOK || strings.Contains(body, "posted-secret") || !strings.Contains(body, `<option value="12" selected>Pentest (id 12)</option>`) {
		t.Fatalf("save = %d\n%s", rec.Code, body)
	}
	if rec := do(r, http.MethodPost, "/defectdojo/test", url.Values{"csrf_token": {"csrf-alice"}}, alice); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "Connection works") || !strings.Contains(rec.Body.String(), `<select name="product_id"`) {
		t.Fatalf("test connection = %d\n%s", rec.Code, rec.Body.String())
	}

	asked := len(ld.asked)
	if rec := do(r, http.MethodGet, "/defectdojo", nil, fa.session(t, "otto")); rec.Code != http.StatusOK || len(ld.asked) != asked ||
		strings.Contains(rec.Body.String(), `name="product_id"`) {
		t.Fatalf("read-only user loaded the lists or sees the form: %d %v", rec.Code, ld.asked)
	}
	rec = do(r, http.MethodPost, "/defectdojo/export", url.Values{"csrf_token": {"csrf-alice"}, "run": {"r1"}}, alice)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<option value="r1" selected>r1</option>`) {
		t.Fatalf("export keeps the picked run = %d\n%s", rec.Code, rec.Body.String())
	}
}

// AC2: without lists the numeric inputs stay, with the hint where the id is in DefectDojo.
func TestDefectDojoFallsBackToIDInputs(t *testing.T) {
	r, fa, _ := newDojoRouter(t)
	body := do(r, http.MethodGet, "/defectdojo", nil, fa.session(t, "alice")).Body.String()
	for _, want := range []string{`<input type="number" name="product_id" min="1" value="2" required>`,
		`<input type="number" name="engagement_id" min="1" value="3" required>`, "2 in /product/2", "3 in /engagement/3",
		"The list of products could not be loaded from DefectDojo", `<select name="run"><option value="">Latest</option></select>`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q\n%s", want, body)
		}
	}
	if strings.Contains(body, `<select name="product_id"`) || strings.Contains(body, "404 Not Found") {
		t.Fatalf("page shows a product select or the raw error\n%s", body)
	}
}

type fakeRoles struct{ roles []auth.Role }

func (f *fakeRoles) ListRoles(context.Context) ([]auth.Role, error) { return f.roles, nil }
func (f *fakeRoles) CreateRole(context.Context, auth.Actor, string, []auth.Permission) error {
	return nil
}
func (f *fakeRoles) UpdateRole(context.Context, auth.Actor, string, []auth.Permission) error {
	return nil
}
func (f *fakeRoles) DeleteRole(context.Context, auth.Actor, string) error { return nil }

// AC3: every permission is described next to its key in the form and in a legend for the columns.
func TestRolesPageDescribesPermissions(t *testing.T) {
	fa := newFakeAuth()
	roles := &fakeRoles{roles: []auth.Role{{Name: auth.RoleAdmin, Builtin: true, Permissions: auth.AllPermissions}, {Name: "auditor"}}}
	r, err := build(Deps{Auth: fa, Roles: roles}, files, features)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rec := do(r, http.MethodGet, "/roles", nil, fa.session(t, "alice"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || inlineStyle.MatchString(body) {
		t.Fatalf("GET /roles = %d\n%s", rec.Code, body)
	}
	legend := body[strings.Index(body, "<h2>Permissions</h2>"):]
	for _, p := range auth.AllPermissions {
		d := template.HTMLEscapeString(p.Description())
		if d == "" {
			t.Fatalf("%s has no description", p)
		}
		if !strings.Contains(body, `value="`+string(p)+`"> <code>`+string(p)+`</code> <span class="muted">`+d+`</span></label>`) {
			t.Errorf("create form lacks the description of %s", p)
		}
		if !strings.Contains(legend, `<dt><code>`+string(p)+`</code></dt><dd>`+d+`</dd>`) {
			t.Errorf("legend lacks %s", p)
		}
	}
}

// AC4: user-owned fields and Edit come first; each finding kind is shown once with a count.
func TestHostPageOwnedFieldsFirstAndKindCounts(t *testing.T) {
	r, _ := newTestRouter(t)
	d := inventory.HostDetail{Run: "r1", Host: inventory.ExportHost{Address: "10.0.0.1", Status: inventory.StatusActive,
		Tags: []string{"dmz"}, Owner: "Web team", Criticality: "high", Notes: "Moving in March", StatusOverride: "inactive",
		Services: []inventory.ExportService{{Port: 80, Protocol: "tcp", State: "open", Status: inventory.StatusActive,
			Findings: []inventory.Finding{
				{SignatureID: "old-nginx", Kind: "outdated", Name: "nginx"},
				{SignatureID: "admin", Kind: "admin-panel", Name: "Admin"},
				{SignatureID: "old-php", Kind: "outdated", Name: "PHP"},
			}}}}}
	render := func(v hostView) string {
		rec := httptest.NewRecorder()
		r.Render(rec, httptest.NewRequest(http.MethodGet, "/hosts/10.0.0.1", nil), http.StatusOK, "host.html", View{Data: v})
		return rec.Body.String()
	}
	v := newHostView(d, time.Now())
	v.Form = newHostForm(d.Host)
	body := render(v)
	row := `<div class="marks"><span class="kind outdated">Outdated version <span class="num">2</span></span><span class="kind admin-panel">Admin panel <span class="num">1</span></span></div>`
	if !strings.Contains(body, row) || inlineStyle.MatchString(body) {
		t.Fatalf("service row lacks %s\n%s", row, body)
	}
	order := []string{`<a class="btn primary" href="/hosts/10.0.0.1?edit=1#edit">Edit host</a>`, `<div class="figures">`,
		"<h2>Owner, tags and notes</h2>", `<span class="tag">dmz</span>`, "<dd>Web team</dd>", "<dd>high</dd>", "<dd>inactive</dd>",
		"<dd>Moving in March</dd>", "<h2>Services</h2>", `<details class="panel" id="edit">`}
	for i := 1; i < len(order); i++ {
		if a, b := strings.Index(body, order[i-1]), strings.Index(body, order[i]); a < 0 || b < a {
			t.Errorf("host page: %q (at %d) must come after %q (at %d)", order[i], b, order[i-1], a)
		}
	}
	v.EditOpen = true
	if body := render(v); !strings.Contains(body, `<details class="panel" id="edit" open>`) {
		t.Errorf("edit=1 does not open the edit form")
	}
	v.Form, v.EditOpen = nil, false
	if body := render(v); strings.Contains(body, "Edit host") || !strings.Contains(body, "<dd>Web team</dd>") {
		t.Errorf("read-only host page shows Edit host or hides the owner")
	}
}

type fakeAudit struct {
	actions []string
	filters []auth.AuditFilter
}

func (f *fakeAudit) ListAudit(_ context.Context, af auth.AuditFilter, _, _ int) ([]auth.AuditEntry, int, error) {
	f.filters = append(f.filters, af)
	return []auth.AuditEntry{{ID: 1, At: time.Now(), Actor: "root", Action: "login"}}, 1, nil
}

func (f *fakeAudit) ListAuditActions(context.Context) ([]string, error) { return f.actions, nil }

// AC5: the Action filter is a select of the actions in the log; Actor stays free text.
func TestAuditActionFilterIsSelect(t *testing.T) {
	fa := newFakeAuth()
	fl := &fakeAudit{actions: []string{"defectdojo.export", "login", "user.create"}}
	r, err := build(Deps{Auth: fa, Audit: fl}, files, features)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	alice := fa.session(t, "alice")
	body := do(r, http.MethodGet, "/audit", nil, alice).Body.String()
	want := `<select name="action"><option value="">Any</option><option value="defectdojo.export">defectdojo.export</option><option value="login">login</option><option value="user.create">user.create</option></select>`
	if !strings.Contains(body, want) || !strings.Contains(body, `<input type="text" name="actor"`) || strings.Contains(body, `<input type="text" name="action"`) {
		t.Fatalf("audit page lacks %s\n%s", want, body)
	}
	body = do(r, http.MethodGet, "/audit?action=login", nil, alice).Body.String()
	if !strings.Contains(body, `<option value="login" selected>login</option>`) || fl.filters[len(fl.filters)-1].Action != "login" {
		t.Fatalf("action=login is not selected or not filtered: %+v\n%s", fl.filters, body)
	}
	body = do(r, http.MethodGet, "/audit?action=host.edit", nil, alice).Body.String()
	if !strings.Contains(body, `<option value="host.edit" selected>host.edit</option>`) {
		t.Fatalf("an action from the URL that is not in the log is not kept\n%s", body)
	}
}
