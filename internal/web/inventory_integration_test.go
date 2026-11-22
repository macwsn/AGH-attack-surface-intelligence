//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"fmt"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

type inventorySite struct {
	url     string
	inv     *inventory.Inventory
	handler http.Handler
	deps    Deps
	clients map[string]*http.Client
	cookies map[string]*http.Cookie
	csrf    map[string]string
}

func seedInventorySite(t *testing.T) inventorySite {
	t.Helper()
	return newInventorySite(t, func(ctx context.Context, inv *inventory.Inventory) {
		panel := inventory.ServiceResult{Port: 443, Protocol: "tcp", State: "open", Service: "http", Product: "nginx", Version: "1.27.5",
			HTTP: &probe.HTTP{Scheme: "https", URL: "https://10.0.0.1/", StatusCode: 200, Title: "Portal login",
				Headers: map[string]string{"server": "nginx/1.27.5", "x-debug-token": "secret-123"},
				Cookies: []probe.Cookie{{Name: "PHPSESSID", HTTPOnly: true}},
				TLS:     &probe.TLS{SubjectCN: "panel.example", IssuerCN: "Panel CA", NotAfter: "2030-01-01T00:00:00Z", SelfSigned: true}},
			Technologies: []inventory.Technology{{Name: "nginx", Category: "web-server", Version: "1.27.5", Confidence: 87, Source: "builtin"}},
			Findings: []inventory.Finding{{SignatureID: "admin-panel-login", Kind: "admin-panel", Name: "Admin login form",
				Confidence: 80, Evidence: "form action=/admin/login"}},
		}
		web := func(title string) inventory.ServiceResult {
			return inventory.ServiceResult{Port: 80, Protocol: "tcp", State: "open", Service: "http",
				HTTP:         &probe.HTTP{Scheme: "http", StatusCode: 200, Title: title},
				Technologies: []inventory.Technology{{Name: "nginx", Confidence: 90, Source: "builtin"}}}
		}
		ssh := inventory.ServiceResult{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}
		named := []struct {
			host inventory.HostResult
			seen [3]bool
		}{
			{inventory.HostResult{Address: "10.0.0.1", Hostnames: []string{"panel.example"}, Services: []inventory.ServiceResult{panel}}, [3]bool{true, true, true}},
			{inventory.HostResult{Address: "10.0.0.2", Services: []inventory.ServiceResult{ssh}}, [3]bool{true, true, true}},
			{inventory.HostResult{Address: "10.0.0.3", Services: []inventory.ServiceResult{web("Flapping")}}, [3]bool{true, true, false}},
			{inventory.HostResult{Address: "10.0.0.4", Services: []inventory.ServiceResult{web("Gone")}}, [3]bool{true, false, false}},
			{inventory.HostResult{Address: "10.0.0.10", Services: []inventory.ServiceResult{web("Wiki")}}, [3]bool{true, true, true}},
		}
		var namedAddrs, bulkAddrs []string
		var bulk []inventory.HostResult
		for _, n := range named {
			namedAddrs = append(namedAddrs, n.host.Address)
		}
		for i := 0; i < 60; i++ {
			a := fmt.Sprintf("10.0.1.%d", i)
			bulkAddrs = append(bulkAddrs, a)
			bulk = append(bulk, inventory.HostResult{Address: a, Services: []inventory.ServiceResult{ssh}})
		}
		for r := 0; r < 3; r++ {
			run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: fmt.Sprintf("l%d", r+1), InactiveAfter: 2})
			if err != nil {
				t.Fatalf("CreateRun: %v", err)
			}
			var hosts []inventory.HostResult
			for _, n := range named {
				if n.seen[r] {
					hosts = append(hosts, n.host)
				}
			}
			if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: namedAddrs, Hosts: hosts}); err != nil {
				t.Fatalf("RecordGroup: %v", err)
			}
			if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 1, Addresses: bulkAddrs, Hosts: bulk}); err != nil {
				t.Fatalf("RecordGroup: %v", err)
			}
		}
		if err := inv.UpdateHostUserFields(ctx, "10.0.0.1", inventory.HostUserFields{Tags: []string{"dmz"}, DisplayName: "Admin portal",
			Owner: "Web team", Notes: "Moving in March"}); err != nil {
			t.Fatalf("UpdateHostUserFields: %v", err)
		}
	})
}

func newInventorySite(t *testing.T, seed func(ctx context.Context, inv *inventory.Inventory)) inventorySite {
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
	inv := inventory.New(st, keys)
	seed(ctx, inv)
	svc := auth.NewService(st, auth.Config{})
	deps := Deps{Store: st, Keyring: keys, Auth: svc}
	h, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	site := inventorySite{url: srv.URL, inv: inv, handler: h, deps: deps, clients: map[string]*http.Client{},
		cookies: map[string]*http.Cookie{}, csrf: map[string]string{}}
	base, _ := url.Parse(srv.URL)
	for _, role := range []string{auth.RoleViewer, auth.RoleOperator, auth.RoleEditor, auth.RoleAdmin} {
		user, pass := role+"-user", role+"-password-123"
		if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, user, pass, role); err != nil {
			t.Fatalf("CreateUser %s: %v", role, err)
		}
		sess, err := svc.Login(ctx, user, pass, "local")
		if err != nil {
			t.Fatalf("Login %s: %v", role, err)
		}
		jar, _ := cookiejar.New(nil)
		jar.SetCookies(base, []*http.Cookie{{Name: auth.SessionCookieName, Value: sess.Token, Path: "/"}})
		site.clients[role] = &http.Client{Jar: jar}
		site.cookies[role] = &http.Cookie{Name: auth.SessionCookieName, Value: sess.Token}
		site.csrf[role] = sess.CSRFToken
	}
	return site
}

var hostLink = regexp.MustCompile(`<a class="addr" href="/hosts/([^"]+)">`)

func listedHosts(body string) []string {
	out := []string{}
	for _, m := range hostLink.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

func checkPageIsSafe(t *testing.T, what, body string) {
	t.Helper()
	if externalRef.MatchString(body) {
		t.Errorf("%s references an external resource: %s", what, externalRef.FindString(body))
	}
	if regexp.MustCompile(`<script>|<script [^>]*>[^<]`).MatchString(body) || strings.Contains(body, "style=") {
		t.Errorf("%s has inline script or style", what)
	}
}

// REQ-WEB-020
func TestHostsListPerRole(t *testing.T) {
	site := seedInventorySite(t)
	for role, c := range site.clients {
		t.Run(role, func(t *testing.T) {
			resp, body := get(t, c, site.url+"/hosts")
			if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/hosts/" {
				t.Fatalf("GET /hosts = %d at %s", resp.StatusCode, resp.Request.URL)
			}
			checkPageIsSafe(t, "hosts", body)
			got := listedHosts(body)
			if len(got) != 50 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" || got[4] != "10.0.0.10" || got[5] != "10.0.1.0" {
				t.Errorf("first page = %v", got)
			}
			if !strings.Contains(body, "Showing 1-50 of 65") || !strings.Contains(body, `href="/hosts/?page=2" rel="next"`) {
				t.Errorf("first page lacks the result line or next link")
			}
		})
	}
}

// REQ-WEB-020
func TestHostsListFiltersSortAndPages(t *testing.T) {
	site := seedInventorySite(t)
	c := site.clients[auth.RoleViewer]
	cases := []struct {
		query string
		want  []string
	}{
		{"status=active&service=http", []string{"10.0.0.1", "10.0.0.10"}},
		{"status=unstable", []string{"10.0.0.3"}},
		{"status=inactive", []string{"10.0.0.4"}},
		{"port=443", []string{"10.0.0.1"}},
		{"technology=nginx&sort=address&dir=desc", []string{"10.0.0.10", "10.0.0.4", "10.0.0.3", "10.0.0.1"}},
		{"finding=admin-panel", []string{"10.0.0.1"}},
		{"tag=dmz", []string{"10.0.0.1"}},
		{"q=PORTAL", []string{"10.0.0.1"}},
		{"q=wiki", []string{"10.0.0.10"}},
		{"service=http&sort=interest&dir=desc", []string{"10.0.0.1", "10.0.0.3", "10.0.0.4", "10.0.0.10"}},
	}
	for _, tc := range cases {
		resp, body := get(t, c, site.url+"/hosts/?"+tc.query)
		got := listedHosts(body)
		if resp.StatusCode != http.StatusOK || strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("?%s = %d %v, want %v", tc.query, resp.StatusCode, got, tc.want)
		}
	}

	_, body := get(t, c, site.url+"/hosts/?service=ssh&status=active")
	if got := listedHosts(body); len(got) != 50 || !strings.Contains(body, "Showing 1-50 of 61") {
		t.Fatalf("ssh page 1 = %d hosts", len(got))
	}
	next := regexp.MustCompile(`href="([^"]+)" rel="next"`).FindStringSubmatch(body)
	if next == nil {
		t.Fatal("ssh page 1 has no next link")
	}
	nextURL := html.UnescapeString(next[1])
	u, _ := url.Parse(nextURL)
	if q := u.Query(); q.Get("service") != "ssh" || q.Get("status") != "active" || q.Get("page") != "2" {
		t.Errorf("next link %q does not keep the filters", nextURL)
	}
	_, body = get(t, c, site.url+nextURL)
	if got := listedHosts(body); len(got) != 11 || !strings.Contains(body, "Showing 51-61 of 61") || !strings.Contains(body, `rel="prev"`) {
		t.Errorf("ssh page 2 = %v", got)
	}
	if strings.Contains(body, `rel="next"`) {
		t.Errorf("last page has a next link")
	}
	for _, m := range regexp.MustCompile(`<th[^>]*><a href="([^"]+)">`).FindAllStringSubmatch(body, -1) {
		u, _ := url.Parse(html.UnescapeString(m[1]))
		if q := u.Query(); q.Get("service") != "ssh" || q.Get("status") != "active" || q.Get("page") != "" {
			t.Errorf("sort link %q does not keep the filters or keeps the page", m[1])
		}
	}
	if !strings.Contains(body, `<input type="text" name="service" value="ssh"`) || !strings.Contains(body, `<option value="active" selected>`) {
		t.Errorf("filter form does not show the current filter")
	}

	_, body = get(t, c, site.url+"/hosts/?tag=nope")
	if len(listedHosts(body)) != 0 || !strings.Contains(body, `<div class="empty"><p>No hosts match these filters.</p>`) {
		t.Errorf("empty result lacks the empty state")
	}
	_, body = get(t, c, site.url+"/hosts/?page=9")
	if len(listedHosts(body)) != 0 || !strings.Contains(body, "past the last host") {
		t.Errorf("page past the end lacks the empty state")
	}
	resp, body := get(t, c, site.url+"/hosts/?status=gone")
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Status &#34;gone&#34; is not one of") {
		t.Errorf("bad status = %d", resp.StatusCode)
	}
}

// REQ-WEB-021
func TestHostPage(t *testing.T) {
	site := seedInventorySite(t)
	c := site.clients[auth.RoleViewer]
	resp, body := get(t, c, site.url+"/hosts/10.0.0.1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /hosts/10.0.0.1 = %d", resp.StatusCode)
	}
	checkPageIsSafe(t, "host page", body)
	for _, want := range []string{
		`<h1><span class="addr">10.0.0.1</span></h1>`, "Admin portal", "panel.example",
		`<td class="addr">443/tcp</td>`, "<td>open</td>", `<span class="status active">Active</span>`, "nginx 1.27.5",
		"https://10.0.0.1/", `<dd class="num">200</dd>`, "Portal login", "nginx/1.27.5",
		`<td class="addr">x-debug-token</td><td class="wrap">secret-123</td>`, "PHPSESSID; HttpOnly",
		"<dt>Certificate subject</dt><dd>panel.example</dd>", "<dt>Issuer</dt><dd>Panel CA</dd>", "2030-01-01",
		"<dt>Self-signed</dt><dd>Yes</dd>",
		`<td>nginx</td><td>web-server</td><td>1.27.5</td>`, `<progress max="100" value="87"></progress>87`,
		`<span class="kind admin-panel">Admin panel</span>`, "Admin login form", "admin-panel-login", "form action=/admin/login",
		`<span class="tag">dmz</span>`, "Web team", "Moving in March",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("host page lacks %q", want)
		}
	}
	history := regexp.MustCompile(`<tr><td>(l\d)</td><td class="nowrap">[0-9-]+ [0-9:]+ (?:[A-Z]{2,5}|[+-]\d{2,4})</td><td><span class="status \w+">(\w+)</span></td><td class="addr">([^<]*)</td></tr>`)
	var rows []string
	for _, m := range history.FindAllStringSubmatch(body, -1) {
		rows = append(rows, m[1]+" "+m[2]+" "+m[3])
	}
	if want := "l3 Seen 443/tcp|l2 Seen 443/tcp|l1 Seen 443/tcp"; strings.Join(rows, "|") != want {
		t.Errorf("history = %q, want %q", strings.Join(rows, "|"), want)
	}

	_, body = get(t, c, site.url+"/hosts/10.0.0.4")
	rows = nil
	for _, m := range history.FindAllStringSubmatch(body, -1) {
		rows = append(rows, m[1]+" "+m[2]+" "+m[3])
	}
	if want := "l3 Missed |l2 Missed |l1 Seen 80/tcp"; strings.Join(rows, "|") != want {
		t.Errorf("inactive host history = %q, want %q", strings.Join(rows, "|"), want)
	}
	if !strings.Contains(body, `<span class="status inactive">Inactive</span>`) || !strings.Contains(body, "<dt>Server</dt><dd><span class=\"muted\">Not sent</span></dd>") {
		t.Errorf("inactive host page lacks its status or the missing server header")
	}

	for _, path := range []string{"/hosts/10.9.9.9", "/hosts/not-an-address", "/hosts/%3Cscript%3E"} {
		resp, body := get(t, c, site.url+path)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "404 Not Found") || strings.Contains(body, "<script>") {
			t.Errorf("GET %s = %d, want the 404 error page", path, resp.StatusCode)
		}
	}
}

func postForm(h http.Handler, path string, form url.Values, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	if csrf != "" {
		form.Set(auth.CSRFFormField, csrf)
	}
	return do(h, http.MethodPost, path, form, cookie)
}

func editForm() url.Values {
	return url.Values{"tags": {" web , crown-jewel, web ,"}, "display_name": {"Wiki server"}, "owner": {"Docs team"},
		"criticality": {"high"}, "status_override": {"inactive"}, "notes": {"Retire after the migration."}}
}

// REQ-WEB-022
func TestHostEditByOperator(t *testing.T) {
	ctx := context.Background()
	site := seedInventorySite(t)
	const host = "10.0.0.10"

	viewerPage := do(site.handler, http.MethodGet, "/hosts/"+host, nil, site.cookies[auth.RoleViewer]).Body.String()
	if strings.Contains(viewerPage, `id="edit"`) || strings.Contains(viewerPage, `name="tags"`) {
		t.Errorf("viewer sees the edit form")
	}
	opPage := do(site.handler, http.MethodGet, "/hosts/"+host, nil, site.cookies[auth.RoleOperator]).Body.String()
	for _, want := range []string{`<form method="post" action="/hosts/10.0.0.10">`,
		`<input type="hidden" name="csrf_token" value="` + site.csrf[auth.RoleOperator] + `">`, `name="tags"`,
		`name="display_name"`, `name="owner"`, `name="criticality"`, `name="status_override"`, `name="notes"`} {
		if !strings.Contains(opPage, want) {
			t.Errorf("operator host page lacks %q", want)
		}
	}
	checkPageIsSafe(t, "host page with form", opPage)
	order := []string{`<div class="figures">`, "<h2>Services</h2>", "<h2>Service 80/tcp</h2>", "<h2>Response times</h2>", "<h2>History</h2>",
		`<details class="panel" id="edit">`, "<summary>Edit host</summary>", `<form method="post" action="/hosts/10.0.0.10">`}
	for i := 1; i < len(order); i++ {
		if a, b := strings.Index(opPage, order[i-1]), strings.Index(opPage, order[i]); a < 0 || b < a {
			t.Errorf("host page: %q (at %d) must come after %q (at %d)", order[i], b, order[i-1], a)
		}
	}
	for _, once := range []string{`<div class="figures">`, "<h2>Services</h2>", "<h2>History</h2>", `id="edit"`} {
		if n := strings.Count(opPage, once); n != 1 {
			t.Errorf("host page has %q %d times, want once", once, n)
		}
	}
	if strings.Contains(opPage, `id="edit" open`) || strings.Contains(opPage, "<script>") {
		t.Errorf("edit form is open by default or the page has an inline script")
	}

	before, err := site.inv.GetHostUserFields(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 201)
	manyTags := make([]string, 33)
	for i := range manyTags {
		manyTags[i] = fmt.Sprintf("t%d", i)
	}
	for name, c := range map[string]struct {
		field, value, problem string
	}{
		"bad status override": {"status_override", "gone", `Status override &#34;gone&#34; is not one of active, unstable or inactive.`},
		"long owner":          {"owner", long, "The owner is 201 characters long; use at most 200."},
		"long display name":   {"display_name", long, "The display name is 201 characters long; use at most 200."},
		"long tag":            {"tags", "ok, " + strings.Repeat("y", 65), "longer than 64 characters"},
		"too many tags":       {"tags", strings.Join(manyTags, ","), "Use at most 32 tags; this has 33."},
		"bad criticality":     {"criticality", "urgent", `Criticality &#34;urgent&#34; is not one of`},
		"long notes":          {"notes", strings.Repeat("n", 10001), "The notes are 10001 characters long"},
	} {
		form := editForm()
		form.Set(c.field, c.value)
		rec := postForm(site.handler, "/hosts/"+host, form, site.cookies[auth.RoleOperator], site.csrf[auth.RoleOperator])
		body := rec.Body.String()
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(body, c.problem) ||
			!strings.Contains(body, `<span class="problem">`) || !strings.Contains(body, `aria-invalid="true"`) ||
			!strings.Contains(body, "The changes were not saved.") {
			t.Errorf("%s: POST = %d, want 422 with %q", name, rec.Code, c.problem)
		}
		if !strings.Contains(body, `value="Wiki server"`) && c.field != "display_name" {
			t.Errorf("%s: the form does not keep the submitted values", name)
		}
		if after, _ := site.inv.GetHostUserFields(ctx, host); !reflect.DeepEqual(after, before) {
			t.Errorf("%s: invalid input changed the host: %+v", name, after)
		}
	}

	rec := postForm(site.handler, "/hosts/"+host, editForm(), site.cookies[auth.RoleOperator], "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF token = %d, want 403", rec.Code)
	}
	rec = postForm(site.handler, "/hosts/10.9.9.9", editForm(), site.cookies[auth.RoleOperator], site.csrf[auth.RoleOperator])
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST to unknown host = %d, want 404", rec.Code)
	}

	rec = postForm(site.handler, "/hosts/"+host, editForm(), site.cookies[auth.RoleOperator], site.csrf[auth.RoleOperator])
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/hosts/10.0.0.10?saved=1" {
		t.Fatalf("POST edit = %d %q, want 303 to the host page", rec.Code, rec.Header().Get("Location"))
	}
	want := inventory.HostUserFields{Tags: []string{"web", "crown-jewel"}, DisplayName: "Wiki server", Owner: "Docs team",
		Criticality: "high", StatusOverride: "inactive", Notes: "Retire after the migration."}
	if got, err := site.inv.GetHostUserFields(ctx, host); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("GetHostUserFields = %+v, %v; want %+v", got, err, want)
	}
	_, page := get(t, site.clients[auth.RoleOperator], site.url+"/hosts/"+host+"?saved=1")
	for _, s := range []string{`<div class="notice ok">Saved.`, `<span class="tag">web</span>`, `<span class="tag">crown-jewel</span>`,
		"Wiki server", "Docs team", "<dd>high</dd>", "<dd>inactive</dd>", "Retire after the migration.",
		`value="web, crown-jewel"`, `<option value="high" selected>`, `<option value="inactive" selected>`} {
		if !strings.Contains(page, s) {
			t.Errorf("host page after save lacks %q", s)
		}
	}
	_, list := get(t, site.clients[auth.RoleViewer], site.url+"/hosts/?tag=crown-jewel")
	if got := listedHosts(list); strings.Join(got, " ") != host {
		t.Errorf("tag filter after edit = %v, want [%s]", got, host)
	}
	_, list = get(t, site.clients[auth.RoleViewer], site.url+"/hosts/?q=wiki+server")
	if got := listedHosts(list); strings.Join(got, " ") != host {
		t.Errorf("text filter on the new display name = %v", got)
	}
}

// REQ-WEB-022
func TestHostEditDuringRun(t *testing.T) {
	ctx := context.Background()
	site := seedInventorySite(t)
	const host = "10.0.0.1"
	group0 := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.10"}
	scanned := inventory.HostResult{Address: host, Hostnames: []string{"rescanned.example"},
		Services: []inventory.ServiceResult{{Port: 8443, Protocol: "tcp", State: "open", Service: "http"}}}

	run, err := site.inv.CreateRun(ctx, inventory.RunSpec{Name: "live", InactiveAfter: 2})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != inventory.RunRunning {
		t.Fatalf("run status = %s, want running", run.Status)
	}
	started := make(chan struct{})
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		for i := 0; i < 20; i++ {
			g := inventory.GroupResult{Index: 0, Addresses: group0, Hosts: []inventory.HostResult{scanned}}
			if i%2 == 1 {
				g = inventory.GroupResult{Index: 1, Addresses: []string{"10.0.1.0", "10.0.1.1"}}
			}
			if err := site.inv.RecordGroup(ctx, run.ID, g); err != nil {
				errs <- err
				return
			}
			if i == 0 {
				close(started)
			}
		}
	}()
	<-started
	rec := postForm(site.handler, "/hosts/"+host, editForm(), site.cookies[auth.RoleEditor], site.csrf[auth.RoleEditor])
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("edit during the run = %d:\n%s", rec.Code, rec.Body.String())
	}
	if err := <-errs; err != nil {
		t.Fatalf("RecordGroup during the edit: %v", err)
	}
	if err := site.inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: group0, Hosts: []inventory.HostResult{scanned}}); err != nil {
		t.Fatal(err)
	}
	if err := site.inv.SetRunStatus(ctx, run.ID, inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
	want := inventory.HostUserFields{Tags: []string{"web", "crown-jewel"}, DisplayName: "Wiki server", Owner: "Docs team",
		Criticality: "high", StatusOverride: "inactive", Notes: "Retire after the migration."}
	if got, err := site.inv.GetHostUserFields(ctx, host); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("after the run: %+v, %v; want %+v", got, err, want)
	}
	_, page := get(t, site.clients[auth.RoleViewer], site.url+"/hosts/"+host)
	if !strings.Contains(page, "rescanned.example") || !strings.Contains(page, "8443/tcp") || !strings.Contains(page, "Wiki server") {
		t.Errorf("host page after the run lacks the scan result or the edit")
	}
	_, list := get(t, site.clients[auth.RoleViewer], site.url+"/hosts/?tag=crown-jewel&port=8443")
	if got := listedHosts(list); strings.Join(got, " ") != host {
		t.Errorf("list after the run = %v, want [%s]", got, host)
	}
}

// REQ-WEB-020
func TestHostsListMarksNonActivePorts(t *testing.T) {
	site := newInventorySite(t, func(ctx context.Context, inv *inventory.Inventory) {
		ssh := inventory.ServiceResult{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}
		web := inventory.ServiceResult{Port: 8080, Protocol: "tcp", State: "open", Service: "http"}
		for r, withWeb := range []bool{true, true, false} {
			run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: fmt.Sprintf("m%d", r+1), InactiveAfter: 2})
			if err != nil {
				t.Fatalf("CreateRun: %v", err)
			}
			mixed := inventory.HostResult{Address: "10.0.0.1", Services: []inventory.ServiceResult{ssh}}
			if withWeb {
				mixed.Services = append(mixed.Services, web)
			}
			hosts := []inventory.HostResult{mixed, {Address: "10.0.0.2", Services: []inventory.ServiceResult{ssh}}}
			if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.1", "10.0.0.2"}, Hosts: hosts}); err != nil {
				t.Fatalf("RecordGroup: %v", err)
			}
		}
	})
	_, body := get(t, site.clients[auth.RoleViewer], site.url+"/hosts/")
	rows := strings.Split(body, "<tr")
	var mixed, plain string
	for _, r := range rows {
		if strings.Contains(r, `href="/hosts/10.0.0.1"`) {
			mixed = r
		}
		if strings.Contains(r, `href="/hosts/10.0.0.2"`) {
			plain = r
		}
	}
	if !strings.Contains(mixed, `<td class="addr">22, <span class="status unstable" title="Unstable service">8080</span></td>`) {
		t.Errorf("mixed host row does not mark the unstable port:\n%s", mixed)
	}
	if !strings.Contains(plain, `<td class="addr">22</td>`) {
		t.Errorf("active-only host row changed:\n%s", plain)
	}
	if !strings.Contains(body, "2 hosts in the inventory.") {
		t.Errorf("lede lacks '2 hosts in the inventory.'")
	}
	_, one := get(t, site.clients[auth.RoleViewer], site.url+"/hosts/?q=10.0.0.2")
	if !strings.Contains(one, "1 matching host.") {
		t.Errorf("filtered lede lacks '1 matching host.'")
	}
}

func (e *leakEnv) addRole(t *testing.T, name string, perms ...auth.Permission) {
	t.Helper()
	if err := e.svc.CreateRole(context.Background(), auth.Actor{Username: "setup", Addr: "local"}, name, perms); err != nil {
		t.Fatalf("CreateRole %s: %v", name, err)
	}
	e.addSession(t, name, name)
}

func (e *leakEnv) hostTags(t *testing.T, address string) []string {
	t.Helper()
	var tags []string
	if err := e.st.Pool.QueryRow(context.Background(), `SELECT tags FROM hosts WHERE address = $1`, address).Scan(&tags); err != nil {
		t.Fatalf("tags of %s: %v", address, err)
	}
	return tags
}

// REQ-WEB-053
func TestHostInvalidEditWithoutReadShowsNoHost(t *testing.T) {
	e := newLeakEnv(t)
	bad := url.Values{"tags": {strings.Repeat("x", 500)}}
	existing, _, body := e.post("editonly", "/hosts/"+auditHost, bad)
	missing, _, missingBody := e.post("editonly", "/hosts/10.9.9.9", bad)
	if existing == http.StatusUnprocessableEntity || existing != missing {
		t.Errorf("invalid edit without inventory.read: existing = %d, missing = %d, want the same answer and not 422", existing, missing)
	}
	for _, b := range []string{body, missingBody} {
		if got := e.leaks(b); len(got) > 0 || strings.Contains(b, "ssh") || strings.Contains(b, "22/tcp") || strings.Contains(b, "Response times") {
			t.Errorf("invalid edit without inventory.read shows host data %q\n%.400s", got, b)
		}
		if !strings.Contains(b, "longer than 64 characters") {
			t.Errorf("invalid edit without inventory.read does not name the problem\n%.400s", b)
		}
	}
	if tags := e.hostTags(t, auditHost); len(tags) != 0 {
		t.Errorf("tags after a rejected edit = %v", tags)
	}
	code, loc, _ := e.post("editonly", "/hosts/"+auditHost, url.Values{"tags": {"web, dmz"}})
	if code != http.StatusSeeOther || loc != "/hosts/"+auditHost+"?saved=1" {
		t.Errorf("valid edit without inventory.read = %d %q, want 303 to the saved host page", code, loc)
	}
	if tags := e.hostTags(t, auditHost); !reflect.DeepEqual(tags, []string{"web", "dmz"}) {
		t.Errorf("tags after a valid edit = %v", tags)
	}
	code, _, body = e.post(auth.RoleOperator, "/hosts/"+auditHost, bad)
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, auditTitle) || !strings.Contains(body, "longer than 64 characters") {
		t.Errorf("invalid edit with inventory.read = %d, want 422 with the host page and the problem\n%.400s", code, body)
	}
}

func TestHostPageEditOnTop(t *testing.T) {
	site := seedInventorySite(t)
	const host = "10.0.0.10"
	op := do(site.handler, http.MethodGet, "/hosts/"+host, nil, site.cookies[auth.RoleOperator]).Body.String()
	order := []string{`href="/hosts/10.0.0.10?edit=1#edit">Edit host</a>`, `<div class="figures">`, "<h2>Owner, tags and notes</h2>", "<h2>Services</h2>"}
	for i := 1; i < len(order); i++ {
		if a, b := strings.Index(op, order[i-1]), strings.Index(op, order[i]); a < 0 || b < a {
			t.Errorf("host page: %q (at %d) must come after %q (at %d)", order[i], b, order[i-1], a)
		}
	}
	if strings.Contains(op, `id="edit" open`) {
		t.Errorf("edit form open without edit=1")
	}
	if open := do(site.handler, http.MethodGet, "/hosts/"+host+"?edit=1", nil, site.cookies[auth.RoleOperator]).Body.String(); !strings.Contains(open, `<details class="panel" id="edit" open>`) {
		t.Errorf("edit=1 does not open the edit form")
	}
	viewer := do(site.handler, http.MethodGet, "/hosts/"+host+"?edit=1", nil, site.cookies[auth.RoleViewer]).Body.String()
	if strings.Contains(viewer, "edit=1") || strings.Contains(viewer, `id="edit"`) || !strings.Contains(viewer, "<h2>Owner, tags and notes</h2>") {
		t.Errorf("viewer sees the edit action or misses the owned fields")
	}
}
