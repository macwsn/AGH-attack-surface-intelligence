//go:build integration

package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/schedule"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

// A Wednesday afternoon: outside every window the tests store, so the scheduler starts nothing on its own.
var quietNow = time.Date(2026, 11, 18, 16, 0, 0, 0, time.UTC)

type planResolver map[string][]netip.Addr

func (r planResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("no such host %q", host)
}

type createEnv struct {
	t      *testing.T
	ctx    context.Context
	st     *store.Store
	defs   *schedule.Store
	router *Router
	runner *nmaptest.Runner
	url    string
}

func newCreateEnv(t *testing.T, allowScans bool) *createEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(st, auth.Config{})
	if err := svc.CreateRole(ctx, auth.Actor{Username: "test", Addr: "local"}, "configurer", []auth.Permission{auth.PermScanConfigure}); err != nil {
		t.Fatal(err)
	}
	for user, role := range map[string]string{"alice": auth.RoleAdmin, "eddie": auth.RoleEditor, "victor": auth.RoleViewer, "cora": "configurer"} {
		if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, user, user+"-password-123", role); err != nil {
			t.Fatal(err)
		}
	}
	runner := &nmaptest.Runner{}
	if !allowScans {
		runner.DiscoverFunc = func(_ context.Context, addrs []string, _ nmap.Options) ([]nmap.Host, error) {
			t.Errorf("nmap discovery called for %v", addrs)
			return nil, nil
		}
		runner.ServicesFunc = func(_ context.Context, addrs []string, _ []int, _ nmap.Options) ([]nmap.Host, error) {
			t.Errorf("nmap service scan called for %v", addrs)
			return nil, nil
		}
	}
	defs := schedule.NewStore(st, keys)
	scanner := &scan.Scanner{Store: inventory.New(st, keys), Runner: runner, Resolver: planResolver{"gw": {netip.MustParseAddr("10.0.0.20")}}}
	sched := &schedule.Scheduler{Store: defs, Scanner: scanner, Now: func() time.Time { return quietNow }, Logf: t.Logf}
	sched.Start(ctx)
	t.Cleanup(sched.Wait)
	t.Cleanup(cancel)
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Scans: sched})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &createEnv{t: t, ctx: ctx, st: st, defs: defs, router: h, runner: runner, url: srv.URL}
}

func (e *createEnv) signIn(user string) *browser {
	return signIn(e.t, e.url, user, user+"-password-123")
}

func (e *createEnv) count(table string) int {
	e.t.Helper()
	var n int
	if err := e.st.Pool.QueryRow(e.ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *createEnv) definition(loc string) schedule.Definition {
	e.t.Helper()
	m := regexp.MustCompile(`^/scans/(\d+)\?msg=`).FindStringSubmatch(loc)
	if m == nil {
		e.t.Fatalf("redirect %q is not a scan page", loc)
	}
	var id int64
	fmt.Sscan(m[1], &id)
	d, err := e.defs.Definition(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func (e *createEnv) named(name string) schedule.Definition {
	e.t.Helper()
	list, err := e.defs.Definitions(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, d := range list {
		if d.Name == name {
			return d
		}
	}
	e.t.Fatalf("no definition named %q", name)
	return schedule.Definition{}
}

type formFile struct {
	name string
	data string
}

func (b *browser) send(path string, body io.Reader, contentType string, hx bool) (int, string, string) {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.base+path, body)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(auth.CSRFHeader, b.csrf)
	if hx {
		req.Header.Set("HX-Request", "true")
	}
	c := *b.c
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		b.t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	loc := resp.Header.Get("Location")
	if hx && loc == "" {
		loc = resp.Header.Get("HX-Redirect")
	}
	return resp.StatusCode, loc, string(out)
}

func (b *browser) multipart(path string, fields url.Values, files map[string]formFile) (int, string, string) {
	b.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, vs := range fields {
		for _, v := range vs {
			if err := mw.WriteField(k, v); err != nil {
				b.t.Fatal(err)
			}
		}
	}
	for field, f := range files {
		w, err := mw.CreateFormFile(field, f.name)
		if err != nil {
			b.t.Fatal(err)
		}
		w.Write([]byte(f.data))
	}
	if err := mw.Close(); err != nil {
		b.t.Fatal(err)
	}
	return b.send(path, &body, mw.FormDataContentType(), false)
}

func (b *browser) hx(path string, form url.Values) (int, string) {
	b.t.Helper()
	code, _, body := b.send(path, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", true)
	return code, body
}

var (
	tagInput    = regexp.MustCompile(`<input\b[^>]*>`)
	tagTextarea = regexp.MustCompile(`(?s)<textarea\b([^>]*)>(.*?)</textarea>`)
	tagSelect   = regexp.MustCompile(`(?s)<select\b([^>]*)>(.*?)</select>`)
	tagOption   = regexp.MustCompile(`<option\b([^>]*)>([^<]*)</option>`)
	tagAttr     = regexp.MustCompile(`([a-zA-Z_:-]+)(?:="([^"]*)")?`)
	anyTag      = regexp.MustCompile(`<[^>]+>`)
)

func attrsOf(tag string) map[string]string {
	out := map[string]string{}
	for _, m := range tagAttr.FindAllStringSubmatch(tag, -1) {
		out[m[1]] = html.UnescapeString(m[2])
	}
	return out
}

func mainForm(t *testing.T, page string) string {
	t.Helper()
	i := strings.Index(page, `<form method="post" action="/scans`)
	if i < 0 {
		t.Fatalf("page has no scan form:\n%s", page)
	}
	j := strings.Index(page[i:], "</form>")
	return page[i : i+j]
}

type selOption struct {
	Value, Label string
	Selected     bool
}

func optionsOf(t *testing.T, page, name string) []selOption {
	t.Helper()
	for _, m := range tagSelect.FindAllStringSubmatch(page, -1) {
		if attrsOf(m[1])["name"] != name {
			continue
		}
		var out []selOption
		for _, o := range tagOption.FindAllStringSubmatch(m[2], -1) {
			a := attrsOf(o[1])
			_, sel := a["selected"]
			out = append(out, selOption{Value: a["value"], Label: html.UnescapeString(o[2]), Selected: sel})
		}
		return out
	}
	t.Fatalf("no select named %s", name)
	return nil
}

func selectedOf(t *testing.T, page, name string) string {
	t.Helper()
	opts := optionsOf(t, page, name)
	for _, o := range opts {
		if o.Selected {
			return o.Value
		}
	}
	return opts[0].Value
}

// formValues returns what a browser submits for the scan form as rendered: every input, checked box, textarea and
// selected option, without the file inputs.
func formValues(t *testing.T, page string) url.Values {
	t.Helper()
	form := mainForm(t, page)
	v := url.Values{}
	for _, tag := range tagInput.FindAllString(form, -1) {
		a := attrsOf(tag)
		name := a["name"]
		if name == "" || name == "csrf_token" || a["type"] == "file" {
			continue
		}
		if a["type"] == "checkbox" || a["type"] == "radio" {
			if _, ok := a["checked"]; !ok {
				continue
			}
		}
		v.Add(name, a["value"])
	}
	for _, m := range tagTextarea.FindAllStringSubmatch(form, -1) {
		v.Add(attrsOf(m[1])["name"], html.UnescapeString(m[2]))
	}
	for _, m := range tagSelect.FindAllStringSubmatch(form, -1) {
		v.Set(attrsOf(m[1])["name"], selectedOf(t, form, attrsOf(m[1])["name"]))
	}
	return v
}

func checkedValues(t *testing.T, page, name string) []string {
	t.Helper()
	var out []string
	for _, tag := range tagInput.FindAllString(mainForm(t, page), -1) {
		a := attrsOf(tag)
		if _, ok := a["checked"]; ok && a["name"] == name {
			out = append(out, a["value"])
		}
	}
	return out
}

func inputAttrs(t *testing.T, page, name string) map[string]string {
	t.Helper()
	for _, tag := range tagInput.FindAllString(page, -1) {
		if a := attrsOf(tag); a["name"] == name {
			return a
		}
	}
	t.Fatalf("no input named %s", name)
	return nil
}

func textOf(fragment string) string {
	return strings.TrimSpace(html.UnescapeString(anyTag.ReplaceAllString(fragment, " ")))
}

func newFormValues(t *testing.T, b *browser, path, name, targets string) url.Values {
	t.Helper()
	code, page := b.get(path)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d", path, code)
	}
	v := formValues(t, page)
	v.Set("name", name)
	v.Set("targets", targets)
	return v
}

func webPorts(t *testing.T) []int {
	t.Helper()
	p, err := scan.ParsePorts("80,443,8000,8080,8443")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func checkSafeDefaults(t *testing.T, d schedule.Definition) {
	t.Helper()
	st := d.Settings
	if d.Enabled || len(d.Schedule.Windows) != 0 || st.MaxRate != scan.DefaultMaxRate || st.Workers != scan.DefaultWorkers ||
		d.InactiveAfter != inventory.DefaultInactiveAfter || st.NoAdaptive || (st.ServiceDetection != "" && st.ServiceDetection != scan.ServiceDetectionStandard) ||
		!slices.Equal(st.Ports, webPorts(t)) || st.RunMode() != inventory.ModeFull {
		t.Errorf("definition %q does not have the safe defaults: enabled=%v windows=%v settings=%+v inactive_after=%d",
			d.Name, d.Enabled, d.Schedule.Windows, st, d.InactiveAfter)
	}
}

// REQ-SCHEDULE-021
func TestQuickScan(t *testing.T) {
	e := newCreateEnv(t, true)
	alice := e.signIn("alice")
	quickForm := regexp.MustCompile(`(?s)<form[^>]*action="/scans/quick"[^>]*>(.*?)</form>`)
	checkForm := func(page string) {
		t.Helper()
		m := quickForm.FindStringSubmatch(page)
		if m == nil || strings.Count(page, `action="/scans/quick"`) != 1 {
			t.Fatalf("scans page has no single quick scan form:\n%s", page)
		}
		if !strings.Contains(m[1], `name="targets"`) || !regexp.MustCompile(`<button[^>]*type="submit"[^>]*>Scan now</button>`).MatchString(m[1]) {
			t.Errorf("quick form lacks targets or the Scan now button:\n%s", m[1])
		}
		var values []string
		for _, o := range optionsOf(t, m[1], "port_preset") {
			values = append(values, o.Value)
			if o.Selected != (o.Value == presetWeb) {
				t.Errorf("option %s selected=%v", o.Value, o.Selected)
			}
		}
		if !slices.Equal(values, []string{"web", "top100", "top1000", "all"}) {
			t.Errorf("quick port sets %v", values)
		}
	}
	_, page := alice.get("/scans")
	checkForm(page)
	if strings.Index(page, `action="/scans/quick"`) > strings.Index(page, "No scans yet.") {
		t.Error("quick form is not above the (empty) scan list")
	}

	code, loc, body := alice.post("/scans/quick", url.Values{"targets": {"10.0.0.0/28"}, "port_preset": {"web"}})
	m := runPath.FindStringSubmatch(loc)
	if code != http.StatusSeeOther || m == nil {
		t.Fatalf("quick scan = %d %q:\n%s", code, loc, body)
	}
	var runID int64
	fmt.Sscan(m[1], &runID)
	run, err := e.defs.Run(e.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	first, err := e.defs.Definition(e.ctx, run.DefinitionID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first.Name, "Quick scan") || run.Settings.Recheck() || !slices.Equal(first.Settings.Targets, []string{"10.0.0.0/28"}) {
		t.Errorf("quick scan definition %q, run recheck=%v, targets %v", first.Name, run.Settings.Recheck(), first.Settings.Targets)
	}
	checkSafeDefaults(t, first)

	code, loc, body = alice.post("/scans/quick", url.Values{"targets": {"10.0.0.0/28"}, "port_preset": {"web"}})
	if code != http.StatusSeeOther || !runPath.MatchString(loc) {
		t.Fatalf("second quick scan of the same targets = %d %q:\n%s", code, loc, body)
	}
	if n := e.count("scan_definitions"); n != 2 {
		t.Fatalf("%d definitions after two quick scans", n)
	}
	list, _ := e.defs.Definitions(e.ctx)
	if list[0].Name == list[1].Name {
		t.Errorf("quick scan names collide: %q", list[0].Name)
	}

	code, _, body = alice.post("/scans/quick", url.Values{"targets": {"not a target!"}, "port_preset": {"web"}})
	if code != http.StatusUnprocessableEntity || !regexp.MustCompile(`name="targets"[^>]*aria-invalid="true"`).MatchString(body) ||
		!regexp.MustCompile(`role="alert">[^<]*line 1: invalid target &#34;not a target!&#34;`).MatchString(body) {
		t.Fatalf("invalid quick scan = %d:\n%s", code, body)
	}
	if n := e.count("scan_definitions"); n != 2 {
		t.Errorf("invalid quick scan stored a definition: %d", n)
	}
	_, page = alice.get("/scans")
	checkForm(page)
	if strings.Index(page, `action="/scans/quick"`) > strings.Index(page, `<table class="data">`) {
		t.Error("quick form is not above the scan list")
	}

	eddie := e.signIn("eddie")
	if code, page := eddie.get("/scans"); code != http.StatusOK || strings.Contains(page, "/scans/quick") {
		t.Errorf("editor without scan.configure sees the quick form (%d)", code)
	}
	victor := e.signIn("victor")
	if code, page := victor.get("/scans"); code != http.StatusForbidden || strings.Contains(page, "/scans/quick") {
		t.Errorf("viewer GET /scans = %d", code)
	}
}

// REQ-SCHEDULE-021
func TestScanFormDefaults(t *testing.T) {
	e := newCreateEnv(t, true)
	alice := e.signIn("alice")
	code, page := alice.get("/scans/new")
	if code != http.StatusOK {
		t.Fatalf("GET /scans/new = %d", code)
	}
	v := formValues(t, page)
	wantTZ := time.Local.String()
	if wantTZ == "Local" || wantTZ == "" {
		wantTZ = "UTC"
	}
	for name, want := range map[string]string{"port_preset": "web", "pace": "normal", "scheduled": "off", "workers": "4",
		"inactive_after": fmt.Sprint(inventory.DefaultInactiveAfter), "service_detection": "standard", "mode": "full",
		"signatures_dir": "", "timezone": wantTZ, "max_rate": ""} {
		if got := v[name]; len(got) != 1 || got[0] != want {
			t.Errorf("new form %s = %v, want %q", name, got, want)
		}
	}
	if !regexp.MustCompile(`name="scheduled" value="off" checked> Run only when started by hand`).MatchString(page) {
		t.Error("the checked schedule state does not read 'Run only when started by hand'")
	}
	v.Set("name", "defaults")
	v.Set("targets", "10.0.0.0/28")
	code, loc, body := alice.multipart("/scans", v, nil)
	if code != http.StatusSeeOther {
		t.Fatalf("create = %d:\n%s", code, body)
	}
	d := e.definition(loc)
	checkSafeDefaults(t, d)

	if code, loc, body := alice.post("/scans/quick", url.Values{"targets": {"10.0.0.0/28"}, "port_preset": {"web"}}); code != http.StatusSeeOther {
		t.Fatalf("quick scan = %d %s:\n%s", code, loc, body)
	}
	var quick schedule.Definition
	list, _ := e.defs.Definitions(e.ctx)
	for _, q := range list {
		if q.ID != d.ID {
			quick = q
		}
	}
	if !reflect.DeepEqual(quick.Settings, d.Settings) || !reflect.DeepEqual(quick.Schedule, d.Schedule) ||
		quick.InactiveAfter != d.InactiveAfter || quick.Enabled != d.Enabled {
		t.Errorf("full form defaults differ from the quick scan:\nform  %+v %+v\nquick %+v %+v", d.Settings, d.Schedule, quick.Settings, quick.Schedule)
	}

	code, loc, _ = alice.send("/scans", strings.NewReader(url.Values{"name": {"via htmx"}, "targets": {"10.0.0.1"}, "port_preset": {"web"},
		"pace": {"normal"}, "workers": {"4"}, "inactive_after": {"3"}, "scheduled": {"off"}, "frequency": {"daily"}}.Encode()),
		"application/x-www-form-urlencoded", true)
	if code != http.StatusOK || !strings.HasPrefix(loc, "/scans/") {
		t.Errorf("htmx create = %d, HX-Redirect %q", code, loc)
	}
}

// REQ-SCHEDULE-012
func TestScanFormTargetsFile(t *testing.T) {
	e := newCreateEnv(t, false)
	alice := e.signIn("alice")
	_, page := alice.get("/scans/new")
	form := mainForm(t, page)
	if !strings.Contains(form, `enctype="multipart/form-data"`) {
		t.Error("scan form is not multipart")
	}
	var placeholder string
	for _, m := range tagTextarea.FindAllStringSubmatch(form, -1) {
		a := attrsOf(m[1])
		switch a["name"] {
		case "targets":
			placeholder = a["placeholder"]
		case "excludes":
			if a["placeholder"] == "" {
				t.Error("excludes has no placeholder")
			}
		}
	}
	for _, re := range []string{`\b\d+\.\d+\.\d+\.\d+/\d+\b`, `\d+\.\d+\.\d+\.\d+-\d+`, `(?m)^\d+\.\d+\.\d+\.\d+$`, `(?m)^[a-z][a-z0-9.-]*\.[a-z]+$`} {
		if !regexp.MustCompile(re).MatchString(placeholder) {
			t.Errorf("targets placeholder %q lacks an example matching %s", placeholder, re)
		}
	}
	for _, name := range []string{"targets_file", "excludes_file"} {
		a := inputAttrs(t, form, name)
		if a["type"] != "file" || !strings.Contains(a["accept"], ".txt") || !strings.Contains(a["accept"], ".csv") {
			t.Errorf("%s input %v", name, a)
		}
	}

	base := newFormValues(t, alice, "/scans/new", "", "")
	post := func(name, targets string, files map[string]formFile) schedule.Definition {
		t.Helper()
		v := url.Values{}
		for k, vs := range base {
			v[k] = vs
		}
		v.Set("name", name)
		v.Set("targets", targets)
		code, loc, body := alice.multipart("/scans", v, files)
		if code != http.StatusSeeOther {
			t.Fatalf("%s = %d:\n%s", name, code, body)
		}
		return e.definition(loc)
	}
	if d := post("txt", "", map[string]formFile{"targets_file": {"targets.txt", "10.0.0.1\n10.0.1.0/30\n"}}); !slices.Equal(d.Settings.Targets, []string{"10.0.0.1", "10.0.1.0/30"}) {
		t.Errorf("text file targets %v", d.Settings.Targets)
	}
	if d := post("csv", "", map[string]formFile{"targets_file": {"targets.csv", "target,comment\n10.0.0.1,web\n10.0.2.0/30,lab\n"}}); !slices.Equal(d.Settings.Targets, []string{"10.0.0.1", "10.0.2.0/30"}) {
		t.Errorf("CSV targets %v", d.Settings.Targets)
	}
	if d := post("address header", "", map[string]formFile{"targets_file": {"hosts.csv", "address\n10.0.3.1\n"}}); !slices.Equal(d.Settings.Targets, []string{"10.0.3.1"}) {
		t.Errorf("CSV with an address header %v", d.Settings.Targets)
	}
	d := post("both", "10.9.0.1\n10.9.0.2", map[string]formFile{"targets_file": {"more.txt", "10.0.0.5\n"}, "excludes_file": {"skip.csv", "address\n10.9.0.2\n"}})
	if !slices.Equal(d.Settings.Targets, []string{"10.9.0.1", "10.9.0.2", "10.0.0.5"}) || !slices.Equal(d.Settings.Excludes, []string{"10.9.0.2"}) {
		t.Errorf("typed and file targets %v, excludes %v", d.Settings.Targets, d.Settings.Excludes)
	}

	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "multipart-*"))
	big := strings.Repeat("10.0.0.1\n", 130_000)
	code, _, body := alice.multipart("/scans", base, map[string]formFile{"targets_file": {"big.txt", big}})
	if code != http.StatusBadRequest || !strings.Contains(body, "Target lists over 1 MB are not accepted.") {
		t.Errorf("file over 1 MB = %d:\n%.400s", code, body)
	}
	if after, _ := filepath.Glob(filepath.Join(os.TempDir(), "multipart-*")); len(after) > len(before) {
		t.Errorf("upload left temporary files: %v", after)
	}
	if n := e.count("scan_definitions"); n != 4 {
		t.Errorf("%d definitions, want 4", n)
	}
}

// REQ-SCHEDULE-012
func TestScanFormInvalidLines(t *testing.T) {
	e := newCreateEnv(t, false)
	alice := e.signIn("alice")
	v := newFormValues(t, alice, "/scans/new", "bad lines", "10.0.0.1\nfoo bar\n10.0.0.2\n\n300.1.1.1")
	code, _, body := alice.multipart("/scans", v, nil)
	targetsProblem := regexp.MustCompile(`(?s)<textarea name="targets"[^>]*aria-invalid="true">[^<]*</textarea><span class="hint">[^<]*</span><span class="problem">([^<]*)</span>`)
	m := targetsProblem.FindStringSubmatch(body)
	if code != http.StatusUnprocessableEntity || m == nil {
		t.Fatalf("invalid lines = %d:\n%s", code, body)
	}
	for _, want := range []string{"line 2: invalid target &#34;foo bar&#34;", "line 5: invalid target &#34;300.1.1.1&#34;"} {
		if !strings.Contains(m[1], want) {
			t.Errorf("targets problem %q lacks %q", m[1], want)
		}
	}

	v.Set("targets", "10.0.0.1")
	code, _, body = alice.multipart("/scans", v, map[string]formFile{"targets_file": {"hosts.csv", "address\n10.0.0.7\n\nnot a target!,x\n"}})
	if m := targetsProblem.FindStringSubmatch(body); code != http.StatusUnprocessableEntity || m == nil ||
		!strings.Contains(m[1], "file hosts.csv, line 4: invalid target &#34;not a target!&#34;") {
		t.Errorf("invalid file line = %d:\n%s", code, body)
	}

	v.Set("excludes", "10.0.0.9\n# lab\nbad exclude!")
	code, _, body = alice.multipart("/scans", v, nil)
	excludesProblem := regexp.MustCompile(`(?s)<textarea name="excludes"[^>]*aria-invalid="true">[^<]*</textarea><span class="hint">[^<]*</span><span class="problem">([^<]*line 3: invalid target &#34;bad exclude!&#34;[^<]*)</span>`)
	if code != http.StatusUnprocessableEntity || !excludesProblem.MatchString(body) {
		t.Errorf("invalid exclude = %d:\n%s", code, body)
	}
	code, _, body = alice.multipart("/scans", v, map[string]formFile{"excludes_file": {"skip.txt", "10.0.0.3\nnope nope\n"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "file skip.txt, line 2: invalid target &#34;nope nope&#34;") {
		t.Errorf("invalid exclude file = %d:\n%s", code, body)
	}
	if n := e.count("scan_definitions"); n != 0 {
		t.Errorf("invalid forms stored %d definitions", n)
	}
}

// REQ-SCHEDULE-013
func TestScanPlanEndpoint(t *testing.T) {
	e := newCreateEnv(t, false)
	alice := e.signIn("alice")
	_, page := alice.get("/scans/new")
	form := mainForm(t, page)
	plan := regexp.MustCompile(`<div id="scan-plan"[^>]*>`).FindString(form)
	a := attrsOf(plan)
	if plan == "" || a["hx-post"] != "/scans/plan" || a["hx-target"] != "this" {
		t.Fatalf("form has no plan target posting to /scans/plan: %q", plan)
	}
	for _, field := range []string{"targets", "excludes", "port_preset", "ports", "pace", "max_rate"} {
		if !strings.Contains(a["hx-trigger"], "change from:[name="+field+"]") {
			t.Errorf("plan is not triggered by changes of %s: %q", field, a["hx-trigger"])
		}
	}

	var probed atomic.Int32
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { probed.Add(1) }))
	defer probe.Close()
	probePort := probe.URL[strings.LastIndex(probe.URL, ":")+1:]

	planFor := func(v url.Values) string {
		t.Helper()
		code, body := alice.hx("/scans/plan", v)
		if code != http.StatusOK || strings.Contains(body, "<html") || strings.Contains(body, "<nav") {
			t.Fatalf("plan %v = %d (want a 200 fragment without layout):\n%s", v, code, body)
		}
		return textOf(body)
	}
	v := url.Values{"targets": {"10.0.0.0/24"}, "excludes": {"10.0.0.0/28"}, "port_preset": {"custom"}, "ports": {"80,443"}, "pace": {"normal"}}
	// 10.0.0.0/24 without its network and broadcast address is 254 addresses; the /28 exclude removes 15 of them.
	want := "239 addresses after excludes, 2 ports, 4 groups, at most 47\u2009322 packets and requests, estimated about 1 min or less at this rate (at most 13 min 42 s if every address answered)"
	hint := "Network and broadcast addresses of a range are not scanned and not counted."
	if got := planFor(v); got != want+"  "+hint {
		t.Errorf("plan\n got %q\nwant %q", got, want+"  "+hint)
	}
	if got := planFor(url.Values{"targets": {"127.0.0.1"}, "port_preset": {"custom"}, "ports": {probePort}, "pace": {"fast"}}); !strings.HasPrefix(got, "1 address after excludes, 1 port, 1 group") {
		t.Errorf("plan of the local probe target %q", got)
	}
	if got := planFor(url.Values{"targets": {"10.0.0.0/15"}, "port_preset": {"web"}, "pace": {"normal"}}); !strings.Contains(got, "above the bound of 65\u2009536 addresses") {
		t.Errorf("no address bound warning: %q", got)
	}
	if got := planFor(url.Values{"targets": {"10.0.0.0/28"}, "port_preset": {"all"}, "pace": {"normal"}}); !strings.Contains(got, "All 65\u2009535 ports are scanned") {
		t.Errorf("no all-ports warning: %q", got)
	}
	if got := planFor(url.Values{"targets": {"10.0.0.0/28"}, "port_preset": {"web"}, "pace": {"normal"}}); strings.Contains(got, "bound") || strings.Contains(got, "All 65") ||
		!strings.HasPrefix(got, "14 addresses after excludes, 5 ports") {
		t.Errorf("small web plan: %q", got)
	}
	if code, body := alice.hx("/scans/plan", url.Values{"targets": {"10.0.0.0/28"}, "port_preset": {"web"}, "pace": {"normal"}}); code != http.StatusOK || strings.Contains(body, "notice") {
		t.Errorf("small web plan renders a notice (%d):\n%s", code, body)
	}
	if _, body := alice.hx("/scans/plan", url.Values{"targets": {"10.0.0.0/28"}, "port_preset": {"all"}, "pace": {"normal"}}); !strings.Contains(body, `class="notice warn"`) {
		t.Errorf("all-ports warning is not a warn notice:\n%s", body)
	}
	if got := planFor(url.Values{"targets": {"10.0.0.1\nnot a target!"}, "port_preset": {"web"}}); !strings.Contains(got, `line 2: invalid target "not a target!"`) || strings.Contains(got, "addresses after") {
		t.Errorf("invalid targets plan: %q", got)
	}
	if got := planFor(url.Values{"targets": {""}, "port_preset": {"web"}}); !strings.HasPrefix(got, "Enter targets") {
		t.Errorf("empty targets plan: %q", got)
	}
	if got := planFor(url.Values{"targets": {"10.0.0.0/28"}, "port_preset": {"web"}, "max_rate": {"10"}}); !strings.Contains(got, "about") {
		t.Errorf("exact rate plan: %q", got)
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("port_preset", "web")
	fw, _ := mw.CreateFormFile("targets_file", "t.txt")
	fw.Write([]byte("10.0.0.1\n10.0.0.2\n"))
	mw.Close()
	if code, _, frag := alice.send("/scans/plan", &body, mw.FormDataContentType(), true); code != http.StatusOK || !strings.HasPrefix(textOf(frag), "2 addresses after excludes") {
		t.Errorf("plan with a target file = %d %q", code, textOf(frag))
	}
	if calls := e.runner.Calls(); len(calls) != 0 || probed.Load() != 0 {
		t.Errorf("plan sent to the network: %d nmap calls, %d HTTP requests", len(calls), probed.Load())
	}
	if d, r := e.count("scan_definitions"), e.count("runs"); d != 0 || r != 0 {
		t.Errorf("plan created %d definitions and %d runs", d, r)
	}

	v = newFormValues(t, alice, "/scans/new", "preview match", "10.0.0.0/24")
	v.Set("excludes", "10.0.0.0/28")
	v.Set("port_preset", "custom")
	v.Set("ports", "80,443")
	code, loc, out := alice.multipart("/scans", v, nil)
	if code != http.StatusSeeOther {
		t.Fatalf("create = %d:\n%s", code, out)
	}
	_, preview := alice.get(strings.TrimSuffix(loc, "?msg=created") + "/preview")
	for _, fig := range []string{`<span class="value">239</span><span class="label">Addresses after excludes</span>`, `<span class="value">about 1 min or less</span><span class="label">Estimated duration</span>`} {
		if !strings.Contains(preview, fig) {
			t.Errorf("preview does not show the plan figure %s", fig)
		}
	}
}

// REQ-SCHEDULE-014
func TestScanFormPortPresets(t *testing.T) {
	e := newCreateEnv(t, false)
	alice := e.signIn("alice")
	_, page := alice.get("/scans/new")
	opts := optionsOf(t, page, "port_preset")
	want := []selOption{
		{"web", "Web: 80, 443, 8000, 8080, 8443", true},
		{"top100", "Top 100: the 100 most common ports", false},
		{"top1000", "Top 1000: the 1\u2009000 most common ports", false},
		{"all", "All: all 65\u2009535 ports", false},
		{"custom", "Custom: the ports you enter, for example 80,443,8000-8100", false},
	}
	if !reflect.DeepEqual(opts, want) {
		t.Errorf("port sets\n got %+v\nwant %+v", opts, want)
	}
	custom := regexp.MustCompile(`(?s)<details class="panel">\s*<summary>Custom ports</summary>\s*<div class="body">\s*<label class="field"><span>[^<]*</span><input type="text" name="ports"[^>]*><span class="hint">[^<]*80,443,8000-8100[^<]*</span>`)
	if !custom.MatchString(page) {
		t.Error("the ports field is not in a closed Custom ports section with the range example")
	}

	base := newFormValues(t, alice, "/scans/new", "", "10.0.0.0/28")
	post := func(name, preset, ports string) (int, string, string) {
		v := url.Values{}
		for k, vs := range base {
			v[k] = vs
		}
		v.Set("name", name)
		v.Set("port_preset", preset)
		v.Set("ports", ports)
		return alice.multipart("/scans", v, nil)
	}
	for preset, c := range map[string]struct {
		ports, spec string
		n           int
	}{
		"web": {spec: "80,443,8000,8080,8443", n: 5}, "top100": {spec: "top100", n: 100}, "top1000": {spec: "top1000", n: 1000},
		"all": {spec: "all", n: 65535}, "custom": {ports: "22,8000-8002", spec: "22,8000,8001,8002", n: 4},
	} {
		code, loc, body := post("preset "+preset, preset, c.ports)
		if code != http.StatusSeeOther {
			t.Fatalf("%s = %d:\n%s", preset, code, body)
		}
		got := e.definition(loc).Settings.Ports
		wantPorts, _ := scan.ParsePorts(c.spec)
		if !slices.Equal(got, wantPorts) || len(got) != c.n {
			t.Errorf("%s stored %d ports, want %d of %q", preset, len(got), c.n, c.spec)
		}
		if again, err := scan.ParsePorts(scan.FormatPorts(got)); err != nil || !slices.Equal(again, got) {
			t.Errorf("%s: %q is not accepted by --ports: %v", preset, scan.FormatPorts(got), err)
		}
		if _, edit := alice.get(strings.TrimSuffix(loc, "?msg=created") + "/edit"); selectedOf(t, edit, "port_preset") != preset {
			t.Errorf("edit form of %s shows %s", preset, selectedOf(t, edit, "port_preset"))
		}
	}
	code, _, body := post("reversed", "custom", "80,9000-8000")
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, `invalid port range &#34;9000-8000&#34;`) {
		t.Errorf("reversed range = %d", code)
	}
	old := url.Values{"name": {"old form"}, "targets": {"10.0.0.1"}, "excludes": {""}, "ports": {"8443,8080"}, "max_rate": {"100"},
		"workers": {"1"}, "inactive_after": {"3"}, "signatures_dir": {""}, "timezone": {"UTC"}, "windows": {""}, "frequency": {"daily"}}
	code, loc, body := alice.post("/scans", old)
	if code != http.StatusSeeOther {
		t.Fatalf("old form = %d:\n%s", code, body)
	}
	if got := e.definition(loc).Settings.Ports; !slices.Equal(got, []int{8080, 8443}) {
		t.Errorf("old form ports %v", got)
	}
}

// REQ-SCHEDULE-015
func TestScanFormPacePresets(t *testing.T) {
	e := newCreateEnv(t, false)
	alice := e.signIn("alice")
	_, page := alice.get("/scans/new")
	pace := regexp.MustCompile(`<label class="check"><input type="radio" name="pace" value="(\w+)"( checked)?> ([^<]*)</label>`)
	var values []string
	for _, m := range pace.FindAllStringSubmatch(page, -1) {
		values = append(values, m[1])
		if (m[2] != "") != (m[1] == "normal") {
			t.Errorf("pace %s checked=%v", m[1], m[2] != "")
		}
		rate := map[string]string{"careful": "20", "normal": "100", "fast": "500"}[m[1]]
		if !strings.Contains(m[3], " "+rate+" packets and requests per second") || strings.Count(strings.TrimSuffix(m[3], "."), ". ") != 1 {
			t.Errorf("pace %s text %q does not state %s per second in one sentence after its name", m[1], m[3], rate)
		}
	}
	if !slices.Equal(values, []string{"careful", "normal", "fast"}) {
		t.Errorf("paces %v", values)
	}
	if n := strings.Count(page, "Adaptive back-off is on"); n != 1 {
		t.Errorf("adaptive back-off described %d times", n)
	}

	base := newFormValues(t, alice, "/scans/new", "", "10.0.0.0/28")
	post := func(name, pace, rate string) (int, string, string) {
		v := url.Values{}
		for k, vs := range base {
			v[k] = vs
		}
		v.Set("name", name)
		v.Set("pace", pace)
		v.Set("max_rate", rate)
		return alice.multipart("/scans", v, nil)
	}
	for pace, want := range map[string]int{"careful": 20, "normal": 100, "fast": 500} {
		code, loc, body := post("pace "+pace, pace, "")
		if code != http.StatusSeeOther {
			t.Fatalf("%s = %d:\n%s", pace, code, body)
		}
		d := e.definition(loc)
		if d.Settings.MaxRate != want || d.Settings.NoAdaptive {
			t.Errorf("%s stored max rate %d, no adaptive %v", pace, d.Settings.MaxRate, d.Settings.NoAdaptive)
		}
		_, edit := alice.get(strings.TrimSuffix(loc, "?msg=created") + "/edit")
		if got := checkedValues(t, edit, "pace"); !slices.Equal(got, []string{pace}) || inputAttrs(t, edit, "max_rate")["value"] != "" {
			t.Errorf("edit form of %s shows pace %v, exact rate %q", pace, got, inputAttrs(t, edit, "max_rate")["value"])
		}
	}
	code, loc, body := post("exact", "fast", "37")
	if code != http.StatusSeeOther || e.definition(loc).Settings.MaxRate != 37 {
		t.Fatalf("exact rate = %d:\n%s", code, body)
	}
	_, edit := alice.get(strings.TrimSuffix(loc, "?msg=created") + "/edit")
	if inputAttrs(t, edit, "max_rate")["value"] != "37" {
		t.Error("edit form does not show the exact rate 37")
	}
	code, _, body = post("rate one", "normal", "1")
	if code != http.StatusUnprocessableEntity || !maxRateProblem.MatchString(body) {
		t.Errorf("rate 1 = %d, no 'at least 2' problem under max_rate:\n%s", code, body)
	}
}

// REQ-SCHEDULE-016
func TestScanFormStructure(t *testing.T) {
	e := newCreateEnv(t, false)
	alice := e.signIn("alice")
	sections := func(page string) map[string]string {
		t.Helper()
		heads := regexp.MustCompile(`<details class="panel"( open)?>\s*<summary>(Basic|Schedule|Advanced)</summary>`).FindAllStringSubmatchIndex(page, -1)
		if len(heads) != 3 || page[heads[0][4]:heads[0][5]] != "Basic" || page[heads[1][4]:heads[1][5]] != "Schedule" || page[heads[2][4]:heads[2][5]] != "Advanced" {
			t.Fatalf("form does not have the sections Basic, Schedule, Advanced in order:\n%s", page)
		}
		out := map[string]string{}
		for i, h := range heads {
			end := h[0] + strings.Index(page[h[0]:], "</form>")
			if i+1 < len(heads) {
				end = heads[i+1][0]
			}
			name := page[h[4]:h[5]]
			out[name] = page[h[0]:end]
			if h[2] >= 0 {
				out[name+" open"] = "yes"
			}
		}
		return out
	}
	for _, path := range []string{"/scans/new"} {
		_, page := alice.get(path)
		s := sections(page)
		if s["Basic open"] == "" || s["Schedule open"] != "" || s["Advanced open"] != "" {
			t.Errorf("%s: open state Basic=%q Schedule=%q Advanced=%q", path, s["Basic open"], s["Schedule open"], s["Advanced open"])
		}
		for section, fields := range map[string][]string{
			"Basic":    {"name", "targets", "excludes", "port_preset", "pace"},
			"Schedule": {"scheduled", "days", "window_start", "window_end", "timezone", "frequency", "recheck_every"},
			"Advanced": {"workers", "inactive_after", "service_detection", "mode", "signatures_dir", "max_rate", "windows"},
		} {
			for _, f := range fields {
				if !strings.Contains(s[section], `name="`+f+`"`) {
					t.Errorf("%s section lacks %s", section, f)
				}
			}
		}
		adv := s["Advanced"]
		for _, f := range []string{"workers", "inactive_after", "service_detection", "mode", "signatures_dir", "max_rate", "windows"} {
			i := strings.Index(adv, `name="`+f+`"`)
			rest := adv[i:]
			if j := strings.Index(rest[1:], `<label class="field">`); j >= 0 {
				rest = rest[:j+1]
			}
			if !regexp.MustCompile(`<span class="hint">[^<]{20,}\.</span>`).MatchString(rest) {
				t.Errorf("advanced field %s has no hint sentence", f)
			}
		}
		if got := optionsOf(t, adv, "service_detection"); len(got) != 2 || got[0].Value != "light" || got[1].Value != "standard" {
			t.Errorf("service detection options %+v", got)
		}
		if got := optionsOf(t, adv, "mode"); len(got) != 2 || got[0].Value != "full" || got[1].Value != "recheck" {
			t.Errorf("mode options %+v", got)
		}
		if input := maxRateInput.FindString(adv); !minTwo.MatchString(input) || !maxRateHint.MatchString(adv) {
			t.Errorf("exact rate input %q lacks min=2 or the hint with the minimum", input)
		}
	}

	v := newFormValues(t, alice, "/scans/new", "problems", "10.0.0.1")
	v.Set("workers", "many")
	_, _, body := alice.multipart("/scans", v, nil)
	if s := sections(body); s["Advanced open"] == "" || s["Schedule open"] != "" {
		t.Errorf("a problem in Advanced does not open it (Schedule open %q)", s["Schedule open"])
	}
	v.Set("workers", "4")
	v.Set("scheduled", "on")
	_, _, body = alice.multipart("/scans", v, nil)
	if s := sections(body); s["Schedule open"] == "" || !strings.Contains(s["Schedule"], `<span class="problem">Choose at least one weekday`) {
		t.Errorf("a problem in Schedule does not open it:\n%s", body)
	}
	_, page := alice.get("/scans/new")
	if regexp.MustCompile(`style\s*=|<script|hx-on`).MatchString(mainForm(t, page)) {
		t.Error("the form uses inline style, script or hx-on")
	}
}

// REQ-SCHEDULE-017
func TestScanScheduleSummary(t *testing.T) {
	e := newCreateEnv(t, false)
	alice := e.signIn("alice")
	_, page := alice.get("/scans/new")
	form := mainForm(t, page)
	if got := checkedValues(t, page, "scheduled"); !slices.Equal(got, []string{"off"}) {
		t.Errorf("scheduled checked %v", got)
	}
	var days []string
	for _, tag := range tagInput.FindAllString(form, -1) {
		if a := attrsOf(tag); a["name"] == "days" && a["type"] == "checkbox" {
			days = append(days, a["value"])
		}
	}
	if !slices.Equal(days, []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}) {
		t.Errorf("weekday checkboxes %v", days)
	}
	for _, name := range []string{"window_start", "window_end"} {
		if inputAttrs(t, form, name)["type"] != "time" {
			t.Errorf("%s is not a time input", name)
		}
	}
	var freq []string
	for _, o := range optionsOf(t, form, "frequency") {
		freq = append(freq, o.Value)
	}
	if !slices.Equal(freq, []string{"daily", "weekly", "interval"}) || len(optionsOf(t, form, "timezone")) < 2 || !strings.Contains(form, `name="recheck_every"`) {
		t.Errorf("frequency %v, timezone or recheck control missing", freq)
	}
	summary := regexp.MustCompile(`<div id="schedule-summary"[^>]*>`).FindString(form)
	if a := attrsOf(summary); a["hx-post"] != "/scans/schedule-summary" || !strings.Contains(a["hx-trigger"], "change from:[name=days]") ||
		!strings.Contains(a["hx-trigger"], "change from:[name=scheduled]") {
		t.Errorf("summary is not recomputed on schedule changes: %q", summary)
	}
	if !strings.Contains(form, `<div id="schedule-summary"`) || !strings.Contains(textOf(form[strings.Index(form, `<div id="schedule-summary"`):]), "Run only when started by hand") {
		t.Error("new form does not render the manual summary")
	}

	sched := url.Values{"scheduled": {"on"}, "days": {"sat"}, "window_start": {"22:00"}, "window_end": {"06:00"}, "frequency": {"weekly"},
		"recheck_every": {"1h"}, "timezone": {"Europe/Warsaw"}}
	summaryFor := func(v url.Values) string {
		t.Helper()
		code, body := alice.hx("/scans/schedule-summary", v)
		if code != http.StatusOK || strings.Contains(body, "<html") {
			t.Fatalf("summary = %d:\n%s", code, body)
		}
		return textOf(body)
	}
	if got := summaryFor(sched); got != "Full scan every Saturday 22:00-06:00; recheck of known services every hour" {
		t.Errorf("summary %q", got)
	}
	sched.Set("recheck_every", "30m")
	if got := summaryFor(sched); got != "Full scan every Saturday 22:00-06:00; recheck of known services every 30 minutes" {
		t.Errorf("summary %q", got)
	}
	sched.Set("recheck_every", "1h")
	off := url.Values{"scheduled": {"off"}, "days": {"sat"}, "window_start": {"22:00"}, "window_end": {"06:00"}, "frequency": {"weekly"}}
	if got := summaryFor(off); got != "Run only when started by hand" {
		t.Errorf("manual summary %q", got)
	}
	if got := summaryFor(url.Values{"scheduled": {"on"}, "frequency": {"daily"}}); !strings.Contains(got, "at least one weekday") {
		t.Errorf("summary without a day %q", got)
	}

	base := newFormValues(t, alice, "/scans/new", "", "10.0.0.0/28")
	post := func(name string, set url.Values, del ...string) (int, string, string) {
		v := url.Values{}
		for k, vs := range base {
			v[k] = vs
		}
		for k, vs := range set {
			v[k] = vs
		}
		for _, k := range del {
			v.Del(k)
		}
		v.Set("name", name)
		return alice.multipart("/scans", v, nil)
	}
	code, loc, body := post("saturday", sched)
	if code != http.StatusSeeOther || !strings.HasSuffix(loc, "?msg=scheduled") {
		t.Fatalf("scheduled create = %d %s:\n%s", code, loc, body)
	}
	d := e.definition(loc)
	wantWin := []schedule.Window{{Days: []time.Weekday{time.Saturday}, Start: "22:00", End: "06:00"}}
	if !d.Enabled || !reflect.DeepEqual(d.Schedule.Windows, wantWin) || d.Schedule.Frequency.Kind != schedule.FrequencyWeekly ||
		d.Schedule.RecheckEvery != "1h" || d.Schedule.Timezone != "Europe/Warsaw" {
		t.Errorf("stored schedule enabled=%v %+v", d.Enabled, d.Schedule)
	}
	_, edit := alice.get(strings.TrimSuffix(loc, "?msg=scheduled") + "/edit")
	if !strings.Contains(edit, "Full scan every Saturday 22:00-06:00; recheck of known services every hour") {
		t.Error("edit form does not render the stored schedule summary")
	}
	if code, _, body := post("no day", url.Values{"scheduled": {"on"}, "windows": {""}}, "days"); code != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "Choose at least one weekday") {
		t.Errorf("scheduled without a day = %d", code)
	}
	set := url.Values{"windows": {"mon-fri 22:00-06:00"}}
	for k, vs := range sched {
		set[k] = vs
	}
	code, loc, body = post("text wins", set)
	if code != http.StatusSeeOther {
		t.Fatalf("windows text = %d:\n%s", code, body)
	}
	if w := e.definition(loc).Schedule.Windows; len(w) != 1 || len(w[0].Days) != 5 || w[0].Days[0] != time.Monday {
		t.Errorf("windows text did not take precedence: %+v", w)
	}
	code, loc, _ = post("by hand", url.Values{"scheduled": {"off"}})
	if d := e.definition(loc); code != http.StatusSeeOther || d.Enabled || len(d.Schedule.Windows) != 0 {
		t.Errorf("manual scan = %d enabled=%v windows=%v", code, d.Enabled, d.Schedule.Windows)
	}
	code, loc, _ = post("no control", sched, "scheduled")
	if d := e.definition(loc); code != http.StatusSeeOther || d.Enabled {
		t.Errorf("form without scheduled = %d enabled=%v", code, d.Enabled)
	}

	path := e.definitionPath(t, "saturday")
	v := formValues(t, edit)
	v.Set("scheduled", "off")
	if code, _, body := alice.multipart(path, v, nil); code != http.StatusSeeOther {
		t.Fatalf("switch off = %d:\n%s", code, body)
	}
	if e.named("saturday").Enabled {
		t.Error("switching the schedule off on edit did not disable the scan")
	}
	v.Set("scheduled", "on")
	if code, _, _ := alice.multipart(path, v, nil); code != http.StatusSeeOther || !e.named("saturday").Enabled {
		t.Error("switching the schedule on on edit did not enable the scan")
	}
	var actions []string
	rows, err := e.st.Pool.Query(e.ctx, `SELECT action FROM audit_log WHERE target = 'saturday' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	if !slices.Contains(actions, "scan.disable") || !slices.Contains(actions, "scan.enable") {
		t.Errorf("enable and disable on edit are not audited: %v", actions)
	}
}

func (e *createEnv) definitionPath(t *testing.T, name string) string {
	t.Helper()
	return fmt.Sprintf("/scans/%d", e.named(name).ID)
}

// REQ-SCHEDULE-018
func TestScanTemplates(t *testing.T) {
	e := newCreateEnv(t, false)
	alice := e.signIn("alice")
	_, page := alice.get("/scans/new")
	for href, label := range map[string]string{"/scans/new?template=single-host": "Single host, all ports",
		"/scans/new?template=large-network": "Large network: weekly full scan, hourly recheck at night"} {
		if !strings.Contains(page, `<a href="`+href+`">`+label+`</a>`) {
			t.Errorf("new page lacks the template link %q", label)
		}
	}
	code, single := alice.get("/scans/new?template=single-host")
	if code != http.StatusOK || selectedOf(t, single, "port_preset") != "all" || !slices.Equal(checkedValues(t, single, "scheduled"), []string{"off"}) ||
		!slices.Equal(checkedValues(t, single, "pace"), []string{"normal"}) {
		t.Errorf("single host template = %d preset %s", code, selectedOf(t, single, "port_preset"))
	}
	code, large := alice.get("/scans/new?template=large-network")
	v := formValues(t, large)
	if code != http.StatusOK || v.Get("port_preset") != "top1000" || v.Get("scheduled") != "on" || !slices.Equal(v["days"], []string{"sat"}) ||
		v.Get("window_start") != "22:00" || v.Get("window_end") != "06:00" || v.Get("frequency") != "weekly" || v.Get("recheck_every") != "1h" ||
		!strings.Contains(large, "Full scan every Saturday 22:00-06:00; recheck of known services every hour") {
		t.Errorf("large network template = %d %v", code, v)
	}
	v.Set("name", "campus weekly")
	v.Set("targets", "10.0.0.0/16")
	code, loc, body := alice.multipart("/scans", v, nil)
	if code != http.StatusSeeOther {
		t.Fatalf("create from template = %d:\n%s", code, body)
	}
	if d := e.definition(loc); !d.Enabled || d.Schedule.Frequency.Kind != schedule.FrequencyWeekly || len(d.Settings.Ports) != 1000 {
		t.Errorf("template definition %+v", d)
	}
	if code, page := alice.get("/scans/new?template=nope"); code != http.StatusOK || selectedOf(t, page, "port_preset") != "web" ||
		!slices.Equal(checkedValues(t, page, "scheduled"), []string{"off"}) {
		t.Errorf("unknown template = %d", code)
	}
}

// REQ-SCHEDULE-019
func TestScanEditKeepsStoredValues(t *testing.T) {
	e := newCreateEnv(t, false)
	alice := e.signIn("alice")
	ports, _ := scan.ParsePorts("22,80,8000-8100")
	windows, err := schedule.ParseWindows("sat 22:00-06:00\nmon-fri 01:00-05:00")
	if err != nil {
		t.Fatal(err)
	}
	orig, err := e.defs.CreateDefinition(e.ctx, auth.Actor{Username: "test", Addr: "local"}, schedule.Definition{
		Name: "kept", Enabled: true, InactiveAfter: 5,
		Settings: inventory.RunSettings{Targets: []string{"10.0.0.0/28", "gw"}, Excludes: []string{"10.0.0.1"}, Ports: ports, MaxRate: 37,
			Workers: 7, ServiceDetection: scan.ServiceDetectionLight, Mode: inventory.ModeFull, GroupSize: 32, HTTPTimeoutMS: 3000, NoAdaptive: true},
		Schedule: schedule.Schedule{Timezone: "America/New_York", Windows: windows,
			Frequency: schedule.Frequency{Kind: schedule.FrequencyInterval, Every: "6h"}, RecheckEvery: "1h"},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/scans/%d", orig.ID)
	code, page := alice.get(path + "/edit")
	if code != http.StatusOK || !regexp.MustCompile(`(?s)<summary>Basic</summary>.*<summary>Schedule</summary>.*<summary>Advanced</summary>`).MatchString(page) {
		t.Fatalf("edit page = %d:\n%s", code, page)
	}
	v := formValues(t, page)
	if v.Get("service_detection") != "light" || v.Get("port_preset") != "custom" || v.Get("ports") != "22,80,8000-8100" ||
		v.Get("max_rate") != "37" || v.Get("timezone") != "America/New_York" || v.Get("scheduled") != "on" ||
		v.Get("windows") != "sat 22:00-06:00\nmon-fri 01:00-05:00" {
		t.Errorf("edit form values %v", v)
	}
	if !strings.Contains(page, "Adaptive back-off is off for this scan") {
		t.Error("edit form claims adaptive back-off for a scan that has it off")
	}
	if !strings.Contains(page, "14 addresses after excludes") {
		t.Errorf("edit form plan does not use the stored targets:\n%s", page[strings.Index(page, `id="scan-plan"`):][:400])
	}
	code, loc, body := alice.multipart(path, v, nil)
	if code != http.StatusSeeOther || !strings.HasSuffix(loc, "?msg=saved") {
		t.Fatalf("save unchanged = %d %s:\n%s", code, loc, body)
	}
	got, err := e.defs.Definition(e.ctx, orig.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Settings, orig.Settings) || !reflect.DeepEqual(got.Schedule, orig.Schedule) ||
		got.InactiveAfter != orig.InactiveAfter || got.Enabled != orig.Enabled {
		t.Errorf("round trip changed the definition:\n got %+v %+v %d %v\nwant %+v %+v %d %v",
			got.Settings, got.Schedule, got.InactiveAfter, got.Enabled, orig.Settings, orig.Schedule, orig.InactiveAfter, orig.Enabled)
	}
	var updates int
	if err := e.st.Pool.QueryRow(e.ctx, `SELECT count(*) FROM audit_log WHERE action IN ('scan.update', 'scan.enable', 'scan.disable')`).Scan(&updates); err != nil || updates != 0 {
		t.Errorf("unchanged save wrote %d audit entries (%v)", updates, err)
	}
	if calls := e.runner.Calls(); len(calls) != 0 {
		t.Errorf("edit page called nmap: %v", calls)
	}
}

// REQ-SCHEDULE-020
func TestScanCreateViewerForbidden(t *testing.T) {
	e := newCreateEnv(t, false)
	d, err := e.defs.CreateDefinition(e.ctx, auth.Actor{Username: "test", Addr: "local"}, schedule.Definition{Name: "existing", InactiveAfter: 3,
		Settings: inventory.RunSettings{Targets: []string{"10.0.0.1"}, Excludes: []string{}, Ports: []int{80}, MaxRate: 100, Workers: 1},
		Schedule: schedule.Schedule{Timezone: "UTC", Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily}}})
	if err != nil {
		t.Fatal(err)
	}
	victor := e.signIn("victor")
	for _, path := range []string{"/scans/new", fmt.Sprintf("/scans/%d/edit", d.ID)} {
		if code, _ := victor.get(path); code != http.StatusForbidden {
			t.Errorf("viewer GET %s = %d, want 403", path, code)
		}
	}
	form := url.Values{"name": {"sneaky"}, "targets": {"10.0.0.0/28"}, "port_preset": {"web"}, "pace": {"normal"}, "workers": {"4"},
		"inactive_after": {"3"}, "scheduled": {"off"}, "frequency": {"daily"}}
	for _, path := range []string{"/scans", "/scans/quick", "/scans/plan", "/scans/schedule-summary", fmt.Sprintf("/scans/%d", d.ID)} {
		if code, _, _ := victor.post(path, form); code != http.StatusForbidden {
			t.Errorf("viewer POST %s = %d, want 403", path, code)
		}
		if code, _ := victor.hx(path, form); code != http.StatusForbidden {
			t.Errorf("viewer htmx POST %s = %d, want 403", path, code)
		}
		if code, _, _ := victor.multipart(path, form, nil); code != http.StatusForbidden {
			t.Errorf("viewer multipart POST %s = %d, want 403", path, code)
		}
	}
	eddie := e.signIn("eddie")
	for _, path := range []string{"/scans/quick", "/scans/plan", "/scans/schedule-summary"} {
		if code, _ := eddie.hx(path, form); code != http.StatusForbidden {
			t.Errorf("editor POST %s = %d, want 403", path, code)
		}
	}
	cora := e.signIn("cora")
	if code, _, body := cora.post("/scans/quick", form); code != http.StatusForbidden || !strings.Contains(body, "does not allow starting scans") {
		t.Errorf("scan.configure without scan.run POST /scans/quick = %d, want 403\n%.300s", code, body)
	}
	if code, _ := cora.hx("/scans/quick", form); code != http.StatusForbidden {
		t.Errorf("scan.configure without scan.run htmx POST /scans/quick = %d, want 403", code)
	}
	if code, _ := cora.hx("/scans/plan", form); code != http.StatusOK {
		t.Errorf("scan.configure POST /scans/plan = %d, want 200", code)
	}
	if n, r := e.count("scan_definitions"), e.count("runs"); n != 1 || r != 0 {
		t.Errorf("forbidden requests left %d definitions and %d runs", n, r)
	}
	want := map[string][]auth.Permission{"GET /scans/new": {auth.PermScanConfigure}, "GET /scans/{id}/edit": {auth.PermScanConfigure},
		"POST /scans": {auth.PermScanConfigure}, "POST /scans/quick": {auth.PermScanConfigure, auth.PermScanRun},
		"POST /scans/plan": {auth.PermScanConfigure}, "POST /scans/schedule-summary": {auth.PermScanConfigure}, "POST /scans/{id}": {auth.PermScanConfigure}}
	for _, rt := range e.router.Routes() {
		key := rt.Method + " " + rt.Path
		perms, ok := want[key]
		if !ok {
			continue
		}
		delete(want, key)
		if p, ok := rt.Access.Permission(); !ok || p != auth.PermScanConfigure {
			t.Errorf("%s access = %s, want scan.configure (and in the handler also %v)", key, rt.Access, perms[1:])
		}
	}
	if len(want) != 0 {
		t.Errorf("routes not registered: %v", want)
	}
}

// REQ-SCHEDULE-014
func TestScanFormCustomPortsReveal(t *testing.T) {
	e := newCreateEnv(t, false)
	alice := e.signIn("alice")
	_, page := alice.get("/scans/new")
	sel := regexp.MustCompile(`<select name="port_preset"[^>]*>`).FindString(page)
	a := attrsOf(sel)
	if a["hx-post"] != "/scans/custom-ports" || a["hx-target"] != "#custom-ports" || a["hx-swap"] != "outerHTML" {
		t.Errorf("port preset select does not ask for the custom ports field: %q", sel)
	}
	if !strings.Contains(page, `<div id="custom-ports">`) {
		t.Error("form has no custom-ports target")
	}
	v := url.Values{"port_preset": {"custom"}, "ports": {"80,443,8000,8080,8443"}}
	code, frag := alice.hx("/scans/custom-ports", v)
	open := regexp.MustCompile(`(?s)^<div id="custom-ports">\s*<details class="panel" open>\s*<summary>Custom ports</summary>.*name="ports" value="80,443,8000,8080,8443"`)
	if code != http.StatusOK || !open.MatchString(frag) {
		t.Errorf("custom-ports with Custom = %d:\n%s", code, frag)
	}
	in := attrsOf(regexp.MustCompile(`<input type="text" name="ports"[^>]*>`).FindString(frag))
	if in["hx-post"] != "/scans/plan" || in["hx-target"] != "#scan-plan" || !strings.HasPrefix(in["hx-trigger"], "change") {
		t.Errorf("swapped ports field does not refresh the plan: %v", in)
	}
	v.Set("port_preset", "top100")
	if code, frag := alice.hx("/scans/custom-ports", v); code != http.StatusOK || !strings.Contains(frag, `<details class="panel">`) || strings.Contains(frag, " open>") {
		t.Errorf("custom-ports with Top 100 = %d:\n%s", code, frag)
	}
	if regexp.MustCompile(`style\s*=`).MatchString(frag) {
		t.Error("fragment has a style attribute")
	}
	victor := e.signIn("victor")
	if code, _ := victor.hx("/scans/custom-ports", v); code != http.StatusForbidden {
		t.Errorf("viewer POST /scans/custom-ports = %d, want 403", code)
	}
	for _, rt := range e.router.Routes() {
		if rt.Method+" "+rt.Path == "POST /scans/custom-ports" {
			if p, ok := rt.Access.Permission(); !ok || p != auth.PermScanConfigure {
				t.Errorf("custom-ports access = %s, want scan.configure", rt.Access)
			}
			return
		}
	}
	t.Error("POST /scans/custom-ports is not registered")
}

// REQ-SCHEDULE-017, REQ-SCHEDULE-019
func TestScanEditKeepsEnabledAnyTime(t *testing.T) {
	e := newCreateEnv(t, false)
	alice := e.signIn("alice")
	orig, err := e.defs.CreateDefinition(e.ctx, auth.Actor{Username: "test", Addr: "local"}, schedule.Definition{
		Name: "any time", Enabled: true, InactiveAfter: 3,
		Settings: inventory.RunSettings{Targets: []string{"10.0.0.0/28"}, Excludes: []string{}, Ports: []int{80, 443, 8000, 8080, 8443}, MaxRate: 100,
			Workers: 4},
		Schedule: schedule.Schedule{Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/scans/%d", orig.ID)
	code, page := alice.get(path + "/edit")
	if code != http.StatusOK || !strings.Contains(page, "the scheduler may start this scan at any time") {
		t.Fatalf("edit page = %d does not say the scan runs at any time", code)
	}
	v := formValues(t, page)
	if v.Get("scheduled") != "on" || len(v["days"]) != 0 || v.Get("windows") != "" {
		t.Errorf("edit form values %v", v)
	}
	if code, frag := alice.hx(fmt.Sprintf("/scans/schedule-summary?scan=%d", orig.ID), v); code != http.StatusOK || strings.Contains(frag, "weekday") {
		t.Errorf("summary = %d %q", code, frag)
	}
	code, loc, body := alice.multipart(path, v, nil)
	if code != http.StatusSeeOther || !strings.HasSuffix(loc, "?msg=saved") {
		t.Fatalf("save unchanged = %d %s:\n%s", code, loc, body)
	}
	got, err := e.defs.Definition(e.ctx, orig.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Settings, orig.Settings) || !reflect.DeepEqual(got.Schedule, orig.Schedule) || !got.Enabled {
		t.Errorf("round trip changed the definition:\n got %+v %+v %v\nwant %+v %+v", got.Settings, got.Schedule, got.Enabled, orig.Settings, orig.Schedule)
	}
	code, _, body = alice.multipart("/scans", url.Values{"name": {"fresh"}, "targets": {"10.0.0.1"}, "port_preset": {"web"}, "pace": {"normal"},
		"workers": {"4"}, "inactive_after": {"3"}, "scheduled": {"on"}, "timezone": {"UTC"}, "frequency": {"daily"}, "window_start": {"22:00"}, "window_end": {"06:00"}}, nil)
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "Choose at least one weekday") {
		t.Errorf("new scan on a schedule without days = %d", code)
	}
}
