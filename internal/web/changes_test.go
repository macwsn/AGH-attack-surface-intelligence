package web

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asi/internal/diff"
	"asi/internal/inventory"
	"asi/internal/probe"
)

type fakeInventory struct {
	runs    []inventory.Run
	exports map[string]inventory.Export
}

func (f *fakeInventory) ListRuns(context.Context) ([]inventory.Run, error) { return f.runs, nil }

func (f *fakeInventory) Export(_ context.Context, name string) (inventory.Export, error) {
	exp, ok := f.exports[name]
	if !ok {
		return inventory.Export{}, fmt.Errorf("export: %w: %q", inventory.ErrUnknownRun, name)
	}
	return exp, nil
}

func titledHost(addr, title string) inventory.ExportHost {
	return inventory.ExportHost{Address: addr, Status: inventory.StatusActive, Services: []inventory.ExportService{{
		Port: 80, Protocol: "tcp", Status: inventory.StatusActive, HTTP: &probe.HTTP{StatusCode: 200, Title: title},
	}}}
}

func newChangesRouter(t *testing.T, inv *fakeInventory) (*Router, *http.Cookie) {
	t.Helper()
	fa := newFakeAuth()
	r, err := build(Deps{Auth: fa, Inventory: inv}, files, features)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return r, fa.session(t, "victor")
}

func sampleInventory() *fakeInventory {
	inv := &fakeInventory{exports: map[string]inventory.Export{}}
	add := func(name string, status inventory.RunStatus, hosts ...inventory.ExportHost) {
		inv.runs = append([]inventory.Run{{ID: int64(len(inv.runs) + 1), Name: name, Status: status}}, inv.runs...)
		inv.exports[name] = inventory.Export{Schema: inventory.ExportSchema, Run: name, Hosts: hosts}
	}
	add("r1", inventory.RunCompleted, titledHost("10.0.0.1", "v1"))
	add("r2", inventory.RunCompleted, titledHost("10.0.0.1", `<b>v2</b>`), titledHost("10.0.0.2", "x"))
	add("r3", inventory.RunRunning, titledHost("10.0.0.3", "x"))
	return inv
}

// REQ-WEB-010 REQ-WEB-012
func TestChangesDefaultsToLastTwoCompletedRuns(t *testing.T) {
	r, viewer := newChangesRouter(t, sampleInventory())
	rec := do(r, http.MethodGet, "/changes", nil, viewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /changes = %d\n%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<option value="r1" selected>r1</option>`,
		`<option value="r2" selected>r2</option>`,
		`<a class="addr" href="/hosts/10.0.0.1/timeline">10.0.0.1</a>`,
		`<a class="addr" href="/hosts/10.0.0.2/timeline">10.0.0.2</a>`,
		`<span class="change new">New host</span>`,
		`<span class="change changed">Changed service</span>`,
		`http.title <del>v1</del> <ins>&lt;b&gt;v2&lt;/b&gt;</ins>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<b>v2</b>") || strings.Contains(body, "10.0.0.3") {
		t.Errorf("page is unescaped or compares the running run:\n%s", body)
	}
	if strings.Contains(body, "style=") || strings.Contains(body, "<style") {
		t.Errorf("page has inline style")
	}
}

// REQ-WEB-012
func TestChangesEmptyState(t *testing.T) {
	one := &fakeInventory{runs: []inventory.Run{{ID: 2, Name: "b", Status: inventory.RunRunning}, {ID: 1, Name: "a", Status: inventory.RunCompleted}},
		exports: map[string]inventory.Export{"a": {}, "b": {}}}
	for name, inv := range map[string]*fakeInventory{"no runs": {}, "one completed run": one} {
		r, viewer := newChangesRouter(t, inv)
		rec := do(r, http.MethodGet, "/changes", nil, viewer)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<div class="empty"><p>Changes appear here once two scan runs have completed.</p></div>`) {
			t.Errorf("%s: %d\n%s", name, rec.Code, rec.Body)
		}
	}
}

// REQ-WEB-012
func TestChangesBadInputs(t *testing.T) {
	r, viewer := newChangesRouter(t, sampleInventory())
	cases := []struct {
		target string
		status int
		want   string
	}{
		{"/changes?type=nope", http.StatusBadRequest, `Unknown change type &#34;nope&#34;`},
		{"/changes?type=%3Cscript%3Ealert(1)%3C/script%3E", http.StatusBadRequest, `Unknown change type &#34;&lt;script&gt;alert(1)&lt;/script&gt;&#34;`},
		{"/changes?from=nope&to=r2", http.StatusNotFound, `Run &#34;nope&#34; does not exist.`},
		{"/changes?from=r1&to=%3Cimg%20src=x%3E", http.StatusNotFound, `Run &#34;&lt;img src=x&gt;&#34; does not exist.`},
		{"/changes?from=r1", http.StatusBadRequest, "Pick both a from run and a to run."},
		{"/changes?to=r1", http.StatusBadRequest, "Pick both a from run and a to run."},
		{"/changes.json?from=r1&to=nope", http.StatusNotFound, `unknown run "nope"`},
		{"/changes.json?from=r1", http.StatusBadRequest, "from and to are required"},
	}
	for _, c := range cases {
		rec := do(r, http.MethodGet, c.target, nil, viewer)
		body := rec.Body.String()
		if rec.Code != c.status || !strings.Contains(body, c.want) {
			t.Errorf("%s = %d, want %d with %q:\n%s", c.target, rec.Code, c.status, c.want, body)
		}
		if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x>") {
			t.Errorf("%s: output is not escaped:\n%s", c.target, body)
		}
	}
}

// REQ-WEB-010
func TestChangesTypeFilterAndExplicitRuns(t *testing.T) {
	r, viewer := newChangesRouter(t, sampleInventory())
	body := do(r, http.MethodGet, "/changes?from=r1&to=r2&type=host_new", nil, viewer).Body.String()
	if !strings.Contains(body, `href="/hosts/10.0.0.2/timeline"`) || strings.Contains(body, `<span class="change changed">`) ||
		!strings.Contains(body, `<option value="host_new" selected>New host</option>`) || !strings.Contains(body, "Showing 1 of 2 changes") {
		t.Errorf("filtered page:\n%s", body)
	}
	if n := strings.Count(body, "<tr data-type="); n != 1 || !strings.Contains(body, `<tr data-type="host_new">`) {
		t.Errorf("filtered page has %d rows:\n%s", n, body)
	}
	body = do(r, http.MethodGet, "/changes?from=r1&to=r3", nil, viewer).Body.String()
	if !strings.Contains(body, `<option value="r3" selected>r3</option>`) || !strings.Contains(body, `<option value="r1" selected>r1</option>`) ||
		!strings.Contains(body, `href="/hosts/10.0.0.3/timeline"`) {
		t.Errorf("explicit runs page:\n%s", body)
	}
}

// REQ-WEB-007
func TestChangesTemplateUsesNoInlineStyle(t *testing.T) {
	b, err := fs.ReadFile(files, "changes.html")
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); strings.Contains(s, "style=") || strings.Contains(s, "<style") {
		t.Error("changes.html has inline style")
	}
}

func fieldChanges(n int) []diff.FieldChange {
	var fs []diff.FieldChange
	for i := range n {
		fs = append(fs, diff.FieldChange{Field: fmt.Sprintf("http.headers.h%d", i), Old: "a", New: "b"})
	}
	return fs
}

func renderChangeRows(t *testing.T, changes ...diff.Change) string {
	t.Helper()
	r, _ := newChangesRouter(t, sampleInventory())
	data := changesData{Total: len(changes)}
	for _, c := range changes {
		data.Rows = append(data.Rows, newChangeRow(c))
	}
	rec := httptest.NewRecorder()
	r.Render(rec, httptest.NewRequest(http.MethodGet, "/changes", nil), http.StatusOK, "changes.html", View{Data: data})
	return rec.Body.String()
}

// REQ-WEB-010
func TestChangeFieldValues(t *testing.T) {
	port := 443
	c := diff.Change{Type: "service_changed", Address: "10.0.0.1", Port: &port, Protocol: "tcp", Fields: []diff.FieldChange{
		{Field: "http.title", Old: "v1", New: "v2"},
		{Field: "http.headers.server", Old: "nginx", New: nil},
		{Field: "http.headers.x-frame-options", Old: nil, New: "DENY"},
	}}
	row := newChangeRow(c)
	if row.HTTPGone || len(row.Fields) != 3 {
		t.Fatalf("row = %+v, want three per-field rows", row)
	}
	body := renderChangeRows(t, c)
	for _, want := range []string{
		`http.title <del>v1</del> <ins>v2</ins>`,
		`http.headers.server <del>nginx</del> <span class="none">(none)</span>`,
		`http.headers.x-frame-options <span class="none">(none)</span> <ins>DENY</ins>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if strings.Contains(body, "HTTP data no longer available") || strings.Contains(body, "<del></del>") || strings.Contains(body, "<ins></ins>") {
		t.Errorf("page collapses partial http changes or renders empty values")
	}
}

// REQ-WEB-010
func TestChangeHTTPDataGone(t *testing.T) {
	port := 80
	gone := diff.Change{Type: "service_changed", Address: "10.0.0.1", Port: &port, Protocol: "tcp", Fields: []diff.FieldChange{
		{Field: "http.status_code", Old: 200, New: nil},
		{Field: "http.title", Old: "Portal", New: ""},
		{Field: "http.headers.server", Old: "nginx", New: nil},
	}}
	body := renderChangeRows(t, gone)
	if n := strings.Count(body, "HTTP data no longer available"); n != 1 {
		t.Errorf("'HTTP data no longer available' shown %d times, want 1", n)
	}
	for _, field := range []string{"http.status_code", "http.title", "http.headers.server"} {
		if strings.Contains(body, field) {
			t.Errorf("page still lists %s", field)
		}
	}
}

// REQ-WEB-010
func TestChangeManyFieldsFold(t *testing.T) {
	port := 80
	five := diff.Change{Type: "service_changed", Address: "10.0.0.1", Port: &port, Protocol: "tcp", Fields: fieldChanges(5)}
	if body := renderChangeRows(t, five); strings.Contains(body, "<details>") || !strings.Contains(body, "http.headers.h4 <del>a</del> <ins>b</ins>") {
		t.Errorf("five fields: want all inline, no disclosure")
	}
	six := diff.Change{Type: "service_changed", Address: "10.0.0.2", Port: &port, Protocol: "tcp", Fields: fieldChanges(6)}
	body := renderChangeRows(t, six)
	if !strings.Contains(body, `<details><summary>6 changed fields</summary>http.headers.h0 <del>a</del> <ins>b</ins>`) ||
		!strings.Contains(body, "http.headers.h5 <del>a</del> <ins>b</ins></details>") {
		t.Errorf("six fields: want all of them inside a disclosure with the count:\n%s", body)
	}
}

// REQ-WEB-010
func TestChangeHTTPDataGoneFromRealDiff(t *testing.T) {
	inv := &fakeInventory{exports: map[string]inventory.Export{}}
	host := titledHost("10.0.0.1", "Portal")
	host.Services[0].HTTP.Headers = map[string]string{"server": "nginx"}
	bare := titledHost("10.0.0.1", "")
	bare.Services[0].HTTP = nil
	inv.runs = []inventory.Run{{ID: 2, Name: "r2", Status: inventory.RunCompleted}, {ID: 1, Name: "r1", Status: inventory.RunCompleted}}
	inv.exports["r1"] = inventory.Export{Schema: inventory.ExportSchema, Run: "r1", Hosts: []inventory.ExportHost{host}}
	inv.exports["r2"] = inventory.Export{Schema: inventory.ExportSchema, Run: "r2", Hosts: []inventory.ExportHost{bare}}
	r, viewer := newChangesRouter(t, inv)
	body := do(r, http.MethodGet, "/changes?from=r1&to=r2", nil, viewer).Body.String()
	if n := strings.Count(body, "HTTP data no longer available"); n != 1 {
		t.Errorf("'HTTP data no longer available' shown %d times, want 1:\n%s", n, body)
	}
	if strings.Contains(body, "http.") || strings.Contains(body, "<details>") {
		t.Errorf("page still lists http fields:\n%s", body)
	}
}

// REQ-WEB-010
func TestChangeHeaderRemovedOnlyKeepsFields(t *testing.T) {
	inv := &fakeInventory{exports: map[string]inventory.Export{}}
	before := titledHost("10.0.0.1", "Portal")
	before.Services[0].HTTP.Headers = map[string]string{"x-frame-options": "DENY"}
	after := titledHost("10.0.0.1", "Portal")
	inv.runs = []inventory.Run{{ID: 2, Name: "r2", Status: inventory.RunCompleted}, {ID: 1, Name: "r1", Status: inventory.RunCompleted}}
	inv.exports["r1"] = inventory.Export{Schema: inventory.ExportSchema, Run: "r1", Hosts: []inventory.ExportHost{before}}
	inv.exports["r2"] = inventory.Export{Schema: inventory.ExportSchema, Run: "r2", Hosts: []inventory.ExportHost{after}}
	r, viewer := newChangesRouter(t, inv)
	body := do(r, http.MethodGet, "/changes?from=r1&to=r2", nil, viewer).Body.String()
	if strings.Contains(body, "HTTP data no longer available") ||
		!strings.Contains(body, `http.headers.x-frame-options <del>DENY</del> <span class="none">(none)</span>`) {
		t.Errorf("a removed header while HTTP still answers must render as a field row:\n%s", body)
	}
}

// REQ-WEB-010: AC5 of T-803xb7cwjk
func TestChangesLinkEachHostToItsPage(t *testing.T) {
	r, viewer := newChangesRouter(t, sampleInventory())
	body := do(r, http.MethodGet, "/changes", nil, viewer).Body.String()
	for _, want := range []string{`<th>Host</th>`, `<a href="/hosts/10.0.0.1">Host page</a>`, `<a href="/hosts/10.0.0.2">Host page</a>`} {
		if !strings.Contains(body, want) {
			t.Errorf("changes page lacks %s:\n%s", want, body)
		}
	}
}
