//go:build integration

package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/exchange/defectdojo"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/scan"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/schedule"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

var (
	formTag     = regexp.MustCompile(`(?s)<form\b([^>]*)>(.*?)</form>`)
	formField   = regexp.MustCompile(`(?s)<input\b[^>]*>|<textarea\b[^>]*>.*?</textarea>|<select\b[^>]*>.*?</select>`)
	formButton  = regexp.MustCompile(`<button\b[^>]*\bform="([^"]+)"[^>]*\bformaction="([^"]+)"`)
	pageLink    = regexp.MustCompile(`href="(/[^"#]*)"`)
	selectedOpt = regexp.MustCompile(`(?s)<option\b[^>]*\bvalue="([^"]*)"[^>]*\bselected`)
	firstOpt    = regexp.MustCompile(`(?s)<option\b[^>]*\bvalue="([^"]*)"`)
	textareaRe  = regexp.MustCompile(`(?s)^<textarea\b[^>]*>(.*?)</textarea>$`)
)

func attrOf(tag, name string) (string, bool) {
	m := regexp.MustCompile(`\b` + name + `="([^"]*)"`).FindStringSubmatch(tag)
	if m == nil {
		return "", false
	}
	return html.UnescapeString(m[1]), true
}

type formField2 struct{ name, value string }

type postForm2 struct {
	page, action string
	multipart    bool
	fields       []formField2
	file         string
}

func (f postForm2) key() string {
	names := make([]string, 0, len(f.fields))
	for _, v := range f.fields {
		names = append(names, v.name)
	}
	return f.action + " " + strings.Join(names, ",")
}

func parsePostForms(page, body string) []postForm2 {
	var out []postForm2
	for _, m := range formTag.FindAllStringSubmatch(body, -1) {
		attrs, inner := m[1], m[2]
		if method, _ := attrOf(attrs, "method"); !strings.EqualFold(method, "post") {
			continue
		}
		action, _ := attrOf(attrs, "action")
		enctype, _ := attrOf(attrs, "enctype")
		f := postForm2{page: page, action: action, multipart: enctype == "multipart/form-data"}
		for _, field := range formField.FindAllString(inner, -1) {
			open := field
			if i := strings.Index(field, ">"); i >= 0 {
				open = field[:i+1]
			}
			name, ok := attrOf(open, "name")
			if !ok {
				continue
			}
			value, _ := attrOf(open, "value")
			switch {
			case strings.HasPrefix(field, "<textarea"):
				value = html.UnescapeString(textareaRe.FindStringSubmatch(field)[1])
			case strings.HasPrefix(field, "<select"):
				value = ""
				if o := selectedOpt.FindStringSubmatch(field); o != nil {
					value = html.UnescapeString(o[1])
				} else if o := firstOpt.FindStringSubmatch(field); o != nil {
					value = html.UnescapeString(o[1])
				}
			default:
				switch typ, _ := attrOf(open, "type"); typ {
				case "file":
					f.file = name
					continue
				case "checkbox", "radio":
					if !strings.Contains(open, " checked") {
						continue
					}
				}
			}
			f.fields = append(f.fields, formField2{name, value})
		}
		out = append(out, f)
		if id, ok := attrOf(attrs, "id"); ok {
			for _, b := range formButton.FindAllStringSubmatch(body, -1) {
				if b[1] == id {
					alt := f
					alt.action = html.UnescapeString(b[2])
					out = append(out, alt)
				}
			}
		}
	}
	return out
}

func (f postForm2) request(t *testing.T, base string, withCSRF bool) *http.Request {
	t.Helper()
	var (
		body        bytes.Buffer
		contentType = "application/x-www-form-urlencoded"
	)
	if f.multipart {
		mw := multipart.NewWriter(&body)
		for _, v := range f.fields {
			if v.name == auth.CSRFFormField && !withCSRF {
				continue
			}
			if err := mw.WriteField(v.name, v.value); err != nil {
				t.Fatal(err)
			}
		}
		if f.file != "" {
			fw, err := mw.CreateFormFile(f.file, "hosts.json")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fw.Write([]byte(`{"schema":"asi.export/v1","hosts":[{"address":"10.0.0.9"}]}`)); err != nil {
				t.Fatal(err)
			}
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		contentType = mw.FormDataContentType()
	} else {
		v := url.Values{}
		for _, fv := range f.fields {
			if fv.name == auth.CSRFFormField && !withCSRF {
				continue
			}
			v.Add(fv.name, fv.value)
		}
		body.WriteString(v.Encode())
	}
	req, err := http.NewRequest(http.MethodPost, base+f.action, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	return req
}

// REQ-WEB-046 REQ-WEB-005 AC4: every POST form of every page reachable by an admin carries the hidden CSRF field and works without
// JavaScript: posted as a plain browser form (no htmx headers), including the multipart file upload, it is accepted;
// the same post without the field is refused.
func TestEveryPostFormWorksWithoutJavaScript(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	cli := auth.Actor{Username: "test", Addr: "local"}
	for user, role := range map[string]string{"alice": auth.RoleAdmin, "bob": auth.RoleViewer} {
		if err := svc.CreateUser(ctx, cli, user, user+"-password-123", role); err != nil {
			t.Fatal(err)
		}
	}
	inv := inventory.New(st, keys)
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "r1", Settings: inventory.RunSettings{Targets: []string{"10.0.0.5"}, Ports: []int{80}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.5"}, Hosts: []inventory.HostResult{{
		Address: "10.0.0.5", Services: []inventory.ServiceResult{{Port: 80, Protocol: "tcp", State: "open", Service: "http",
			HTTP: &probe.HTTP{Scheme: "http", URL: "http://10.0.0.5/", StatusCode: 200, Title: "Grafana"}}},
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := detect.NewLibrary(st, keys, "").Create(ctx, detect.Actor{Username: "test", Addr: "local"},
		"id: db-grafana\nname: Grafana\nkind: technology\nconfidence: 80\nmatch: { all: [ { type: title_regex, value: 'Grafana' } ] }\n", true); err != nil {
		t.Fatal(err)
	}
	sched := &schedule.Scheduler{Store: schedule.NewStore(st, keys), Scanner: &scan.Scanner{Store: inv, Runner: &nmaptest.Runner{}}, Logf: t.Logf}
	if _, err := sched.Store.CreateDefinition(ctx, cli, schedule.Definition{Name: "campus", InactiveAfter: 3,
		Settings: inventory.RunSettings{Targets: []string{"10.0.0.5"}, Ports: []int{80}, MaxRate: 10, Workers: 1},
		Schedule: schedule.Schedule{Timezone: "UTC", Frequency: schedule.Frequency{Kind: schedule.FrequencyDaily}}}); err != nil {
		t.Fatal(err)
	}
	sched.Start(ctx)
	t.Cleanup(sched.Wait)
	dojo := &defectdojo.Service{Store: defectdojo.DBStore{DB: st, Keys: keys}, Inventory: inv, HTTP: &http.Client{}}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Users: svc, Roles: svc, Audit: svc, Inventory: inv, Scans: sched, DefectDojo: dojo})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	srv := server.URL
	alice := signIn(t, srv, "alice", "alice-password-123")

	seen, queued := map[string]bool{"/logout": true}, []string{"/"}
	var forms []postForm2
	formSeen := map[string]bool{}
	harvest := func(page, body string) {
		for _, f := range parsePostForms(page, body) {
			if !formSeen[f.key()] {
				formSeen[f.key()] = true
				forms = append(forms, f)
			}
		}
		for _, m := range pageLink.FindAllStringSubmatch(body, -1) {
			p := html.UnescapeString(m[1])
			if path, _, _ := strings.Cut(p, "?"); !seen[path] && !strings.HasPrefix(path, "/static/") && !strings.HasSuffix(path, ".csv") &&
				!strings.HasSuffix(path, ".json") && len(seen) < 200 {
				seen[path] = true
				queued = append(queued, p)
			}
		}
	}
	for len(queued) > 0 {
		p := queued[0]
		queued = queued[1:]
		if code, body := alice.get(p); code == http.StatusOK {
			harvest(p, body)
		}
	}
	for _, page := range []string{"/scans/", "/hosts/10.0.0.5", "/users/bob/delete", "/signatures/db-grafana", "/import", "/defectdojo"} {
		found := false
		for p := range seen {
			found = found || strings.HasPrefix(p, page)
		}
		if !found {
			t.Errorf("the crawl did not reach %s; seed data or links changed", page)
		}
	}
	order := func(f postForm2) int {
		switch {
		case f.action == "/logout":
			return 2
		case strings.HasSuffix(f.action, "/delete"):
			return 1
		}
		return 0
	}
	client := *alice.c
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	posted := map[string]bool{}
	for i := 0; i < len(forms) && i < 300; i++ {
		sort.SliceStable(forms[i:], func(a, b int) bool { return order(forms[i+a]) < order(forms[i+b]) })
		f := forms[i]
		if !strings.Contains(f.key(), " "+auth.CSRFFormField) && !strings.Contains(f.key(), ","+auth.CSRFFormField) {
			t.Errorf("form %s on %s has no hidden %s field", f.action, f.page, auth.CSRFFormField)
			continue
		}
		resp, err := client.Do(f.request(t, srv, false))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("control: POST %s (from %s) without the CSRF field = %d, want 403", f.action, f.page, resp.StatusCode)
		}
		resp, err = client.Do(f.request(t, srv, true))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		posted[f.action] = true
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized || strings.Contains(string(body), "CSRF token") {
			t.Errorf("POST %s (from %s) as a plain form = %d, want it accepted without JavaScript:\n%s", f.action, f.page, resp.StatusCode, body)
			continue
		}
		if loc := resp.Header.Get("Location"); resp.StatusCode == http.StatusSeeOther && strings.HasPrefix(loc, "/") && f.action != "/logout" {
			if code, body := alice.get(loc); code == http.StatusOK {
				harvest(loc, body)
			}
		}
	}
	for _, action := range []string{"/import", "/hosts/entry", "/scans", "/users/create", "/roles/create", "/signatures/import",
		"/defectdojo/settings", "/hosts/10.0.0.5", "/users/bob/delete", "/logout"} {
		if !posted[action] {
			t.Errorf("no form posting to %s was found and posted", action)
		}
	}
	if !slicesContainsPrefix(posted, "/scans/") || !slicesContainsPrefix(posted, "/signatures/") {
		t.Errorf("forms of the scan and signature pages were not posted: %v", posted)
	}
	t.Logf("posted %d forms without JavaScript", len(forms))
}

func slicesContainsPrefix(set map[string]bool, prefix string) bool {
	for k := range set {
		if strings.HasPrefix(k, prefix) && k != prefix {
			return true
		}
	}
	return false
}
