//go:build integration

package web

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func seedDashboard(t *testing.T) func(ctx context.Context, inv *inventory.Inventory) {
	return func(ctx context.Context, inv *inventory.Inventory) {
		far := time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339)
		soon := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
		finding := func(kind string) []inventory.Finding {
			return []inventory.Finding{{SignatureID: kind + "-sig", Kind: kind, Name: kind + " finding", Confidence: 80}}
		}
		panel := inventory.ServiceResult{Port: 443, Protocol: "tcp", State: "open", Service: "http", Findings: finding("admin-panel"),
			HTTP: &probe.HTTP{Scheme: "https", Title: "Panel", TLS: &probe.TLS{SubjectCN: "panel.example", NotAfter: far, SelfSigned: true}}}
		billing := inventory.ServiceResult{Port: 8443, Protocol: "tcp", State: "open", Service: "http",
			HTTP: &probe.HTTP{Scheme: "https", Title: "Billing", TLS: &probe.TLS{SubjectCN: "billing.example", NotAfter: soon}}}
		http := func(title, kind string) inventory.ServiceResult {
			s := inventory.ServiceResult{Port: 80, Protocol: "tcp", State: "open", Service: "http", HTTP: &probe.HTTP{Scheme: "http", Title: title}}
			if kind != "" {
				s.Findings = finding(kind)
			}
			return s
		}
		ssh := inventory.ServiceResult{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}
		all := []string{"10.4.0.1", "10.4.0.2", "10.4.0.3", "10.4.0.4", "10.4.0.5"}
		record := func(name string, hosts []inventory.HostResult) inventory.Run {
			run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name, InactiveAfter: 2})
			if err != nil {
				t.Fatal(err)
			}
			if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: all, Hosts: hosts}); err != nil {
				t.Fatal(err)
			}
			return run
		}
		r1 := record("d1", []inventory.HostResult{
			{Address: "10.4.0.1", Services: []inventory.ServiceResult{panel, ssh}},
			{Address: "10.4.0.2", Services: []inventory.ServiceResult{http("Staging v1", "staging")}},
			{Address: "10.4.0.3", Services: []inventory.ServiceResult{http("Camera", "iot")}},
			{Address: "10.4.0.4", Services: []inventory.ServiceResult{billing}},
		})
		if err := inv.SetRunStatus(ctx, r1.ID, inventory.RunCompleted); err != nil {
			t.Fatal(err)
		}
		record("d2", []inventory.HostResult{
			{Address: "10.4.0.1", Services: []inventory.ServiceResult{panel}},
			{Address: "10.4.0.2", Services: []inventory.ServiceResult{http("Staging v2", "staging")}},
			{Address: "10.4.0.4", Services: []inventory.ServiceResult{billing}},
			{Address: "10.4.0.5", Services: []inventory.ServiceResult{http("New admin", "admin-panel")}},
		})
	}
}

func figureValue(body, label string) string {
	m := regexp.MustCompile(`<span class="value">([^<]*)</span><span class="label">` + regexp.QuoteMeta(label) + `</span>`).FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

func section(body, heading string) string {
	i := strings.Index(body, "<h2>"+heading+"</h2>")
	if i < 0 {
		return ""
	}
	rest := body[i:]
	if j := strings.Index(rest, "</section>"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// REQ-WEB-009
func TestDashboardShowsInventory(t *testing.T) {
	site := newInventorySite(t, seedDashboard(t))
	resp, body := get(t, site.clients[auth.RoleViewer], site.url+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d", resp.StatusCode)
	}
	checkPageIsSafe(t, "dashboard", body)
	if !strings.Contains(body, `<strong class="username">viewer-user</strong>`) || !strings.Contains(body, `<strong class="role">viewer</strong>`) {
		t.Errorf("dashboard lacks the username and role")
	}
	for label, want := range map[string]string{"Active hosts": "4", "Unstable hosts": "1", "Inactive hosts": "0",
		"Active services": "4", "Unstable services": "2", "Inactive services": "0"} {
		if got := figureValue(body, label); got != want {
			t.Errorf("figure %q = %q, want %q", label, got, want)
		}
	}

	changes := section(body, "Changes in the latest run")
	for _, want := range []string{"Changes appear after the second scan.", "<dt>Running now</dt>", ">d2</a>"} {
		if !strings.Contains(changes, want) {
			t.Errorf("change panel while d2 runs lacks %q:\n%s", want, changes)
		}
	}
	scanBody := body
	runs, err := site.inv.ListRuns(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		if run.Name == "d2" {
			if err := site.inv.SetRunStatus(context.Background(), run.ID, inventory.RunCompleted); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, body = get(t, site.clients[auth.RoleViewer], site.url+"/")
	changes = section(body, "Changes in the latest run")
	bar := regexp.MustCompile(`<span>([^<]+)</span><progress class="bar (\w+)" max="\d+" value="(\d+)"></progress><span class="num">(\d+)</span>`)
	var got []string
	for _, m := range bar.FindAllStringSubmatch(changes, -1) {
		got = append(got, m[1]+"="+m[4]+" "+m[2])
	}
	if want := "New hosts=1 new|Missing hosts=1 missing|Changed services=1 changed|Missing services=1 missing"; strings.Join(got, "|") != want {
		t.Errorf("change bars = %q, want %q", strings.Join(got, "|"), want)
	}

	top := listedHosts(section(body, "Top hosts by interest"))
	if want := "10.4.0.1 10.4.0.5 10.4.0.3 10.4.0.2 10.4.0.4"; strings.Join(top, " ") != want {
		t.Errorf("top hosts = %v, want %s", top, want)
	}
	if !strings.Contains(section(body, "Top hosts by interest"), `<progress max="100" value="50"></progress>50`) {
		t.Errorf("top host lacks its interest score")
	}

	findings := section(body, "Newest admin panels, staging and IoT")
	row := regexp.MustCompile(`<span class="kind ([a-z-]+)">[^<]+</span></td><td><a class="addr" href="/hosts/([^"]+)">`)
	got = nil
	for _, m := range row.FindAllStringSubmatch(findings, -1) {
		got = append(got, m[2]+" "+m[1])
	}
	if want := "10.4.0.5 admin-panel|10.4.0.1 admin-panel|10.4.0.2 staging|10.4.0.3 iot"; strings.Join(got, "|") != want {
		t.Errorf("findings = %q, want %q", strings.Join(got, "|"), want)
	}

	certs := section(body, "Certificates to check")
	if hosts := listedHosts(certs); strings.Join(hosts, " ") != "10.4.0.4 10.4.0.1" ||
		!strings.Contains(certs, "billing.example") || !strings.Contains(certs, `title="`+time.Now().Add(10*24*time.Hour).Local().Format("2006-01-02")) || !strings.Contains(certs, "expires in") ||
		!strings.Contains(certs, `<span class="kind staging">Self-signed</span>`) || !strings.Contains(certs, `<span class="kind admin-panel">Expiring</span>`) {
		t.Errorf("certificates panel = %v\n%s", hosts, certs)
	}

	scan := section(scanBody, "Latest run")
	for _, want := range []string{"<dt>Run</dt><dd>d2</dd>", `<span class="status active">Running</span>`,
		`<dt>Groups recorded</dt><dd class="num">1</dd>`, `<dt>Addresses covered</dt><dd class="num">5</dd>`,
		`<dt>Hosts found</dt><dd class="num">4</dd>`} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan panel lacks %q:\n%s", want, scan)
		}
	}

	for _, role := range []string{auth.RoleOperator, auth.RoleEditor, auth.RoleAdmin} {
		if resp, _ := get(t, site.clients[role], site.url+"/"); resp.StatusCode != http.StatusOK {
			t.Errorf("%s GET / = %d", role, resp.StatusCode)
		}
	}
}

// REQ-WEB-009
func TestDashboardEmptyDatabase(t *testing.T) {
	site := newInventorySite(t, func(context.Context, *inventory.Inventory) {})
	resp, body := get(t, site.clients[auth.RoleViewer], site.url+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / on an empty database = %d", resp.StatusCode)
	}
	for _, want := range []string{"No scan has run yet.", "Changes appear after the second run.",
		"No hosts yet. Hosts appear here after the first scan run.", "No admin panels, staging sites or IoT devices found.",
		"No self-signed or expiring certificates."} {
		if !strings.Contains(body, want) {
			t.Errorf("empty dashboard lacks %q", want)
		}
	}
	if got := figureValue(body, "Active hosts"); got != "0" {
		t.Errorf("active hosts on an empty database = %q", got)
	}
}

func stepsOf(body string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`(?s)<li value="(\d)"><h3>([^<]+)</h3>.*?</li>`).FindAllStringSubmatch(section(body, "Get started"), -1) {
		buttons := regexp.MustCompile(`<a class="btn" href="([^"]+)">`).FindAllStringSubmatch(m[0], -1)
		var hrefs []string
		for _, b := range buttons {
			hrefs = append(hrefs, b[1])
		}
		out = append(out, m[1]+" "+m[2]+" ["+strings.Join(hrefs, " ")+"]")
	}
	return out
}

// REQ-WEB-043
func TestDashboardFirstRunSteps(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewKeyring(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(st, auth.Config{})
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc})
	if err != nil {
		t.Fatal(err)
	}
	session := func(user, role string) *http.Cookie {
		t.Helper()
		if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, user, user+"-password-1", role); err != nil {
			t.Fatal(err)
		}
		sess, err := svc.Login(ctx, user, user+"-password-1", "local")
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.SessionCookieName, Value: sess.Token}
	}
	admin := session("ada", auth.RoleAdmin)
	steps := func(c *http.Cookie) []string {
		t.Helper()
		rec := do(h, http.MethodGet, "/", nil, c)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET / = %d", rec.Code)
		}
		if regexp.MustCompile(`style\s*=`).MatchString(rec.Body.String()) {
			t.Error("dashboard has inline styles")
		}
		return stepsOf(rec.Body.String())
	}
	check := func(what string, got []string, want ...string) {
		t.Helper()
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s: steps = %q, want %q", what, got, want)
		}
	}
	step1 := "1 Create a scan [/scans/new]"
	step2 := "2 Look at hosts and changes [/hosts/ /changes]"
	check("empty database", steps(admin), step1, step2, "3 Add users and roles [/users/ /roles]")

	if _, err := st.Pool.Exec(ctx, `INSERT INTO scan_definitions (name, inactive_after, settings, schedule) VALUES ('weekly', 2, '{}', '{}')`); err != nil {
		t.Fatal(err)
	}
	check("after a scan definition", steps(admin), step2, "3 Add users and roles [/users/ /roles]")

	inv := inventory.New(st, keys)
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	check("while the first run is running", steps(admin), step2, "3 Add users and roles [/users/ /roles]")
	if err := inv.SetRunStatus(ctx, run.ID, inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
	check("after a completed run", steps(admin), "3 Add users and roles [/users/ /roles]")

	if _, err := st.Pool.Exec(ctx, `DELETE FROM runs`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `DELETE FROM scan_definitions`); err != nil {
		t.Fatal(err)
	}
	viewer := session("vic", auth.RoleViewer)
	check("viewer without scan.configure", steps(viewer), "1 Create a scan []", step2)
	check("admin after adding a user", steps(admin), step1, step2)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO scan_definitions (name, inactive_after, settings, schedule) VALUES ('weekly', 2, '{}', '{}')`); err != nil {
		t.Fatal(err)
	}
	if err := inv.SetRunStatus(ctx, mustCreateRun(t, inv, "r2"), inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
	body := do(h, http.MethodGet, "/", nil, admin).Body.String()
	if strings.Contains(body, "Get started") || strings.Contains(body, `class="steps"`) {
		t.Error("the steps block is rendered after every step is done")
	}
}

func mustCreateRun(t *testing.T, inv *inventory.Inventory, name string) int64 {
	t.Helper()
	run, err := inv.CreateRun(context.Background(), inventory.RunSpec{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return run.ID
}

func attentionOf(body string) []string {
	var out []string
	sec := section(body, "Needs attention")
	for _, g := range regexp.MustCompile(`(?s)<div class="attention-group">(.*?)</div>`).FindAllStringSubmatch(sec, -1) {
		label := regexp.MustCompile(`<h3><span class="change \w+">([^<]+)</span></h3>`).FindStringSubmatch(g[1])
		var items []string
		for _, li := range regexp.MustCompile(`<li>(?:<a class="addr" href="[^"]+">|<span class="addr">)([^<]+)<`).FindAllStringSubmatch(g[1], -1) {
			items = append(items, li[1])
		}
		line := label[1] + ": " + strings.Join(items, " ")
		if m := regexp.MustCompile(`<p>(?:<a href="([^"]+)">|<span class="muted">)([^<]+)<`).FindStringSubmatch(g[1]); m != nil {
			line += " (" + m[2] + " " + m[1] + ")"
		}
		out = append(out, line)
	}
	return out
}

// REQ-WEB-044
func TestDashboardNeedsAttention(t *testing.T) {
	site := newInventorySite(t, func(ctx context.Context, inv *inventory.Inventory) {
		seedDashboard(t)(ctx, inv)
		cert := func(days int) inventory.ServiceResult {
			return inventory.ServiceResult{Port: 443, Protocol: "tcp", State: "open", Service: "http", HTTP: &probe.HTTP{Scheme: "https",
				TLS: &probe.TLS{SubjectCN: "c.example", NotAfter: time.Now().Add(time.Duration(days) * 24 * time.Hour).UTC().Format(time.RFC3339)}}}
		}
		run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "d3", InactiveAfter: 2})
		if err != nil {
			t.Fatal(err)
		}
		var hosts []inventory.HostResult
		var addrs []string
		for i, days := range []int{29, 30, 31, 400, 400, 400, 400} {
			a := "10.5.0." + string(rune('1'+i))
			addrs = append(addrs, a)
			hosts = append(hosts, inventory.HostResult{Address: a, Services: []inventory.ServiceResult{cert(days)}})
		}
		if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: addrs, Hosts: hosts}); err != nil {
			t.Fatal(err)
		}
	})
	svc := site.deps.Auth.(*auth.Service)
	ctx := context.Background()
	if err := svc.CreateRole(ctx, auth.Actor{Username: "test"}, "exporter", []auth.Permission{auth.PermExport}); err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test"}, "exp", "exp-password-123", "exporter"); err != nil {
		t.Fatal(err)
	}
	sess, err := svc.Login(ctx, "exp", "exp-password-123", "local")
	if err != nil {
		t.Fatal(err)
	}

	_, body := get(t, site.clients[auth.RoleViewer], site.url+"/")
	if i, j := strings.Index(body, "<h2>Needs attention</h2>"), strings.Index(body, `<div class="figures">`); i < 0 || i > j {
		t.Fatalf("the dashboard does not lead with Needs attention:\n%s", body)
	}
	got := attentionOf(body)
	want := []string{
		"New hosts: 10.5.0.1 10.5.0.2 10.5.0.3 10.5.0.4 10.5.0.5 (2 more /changes)",
		"Certificates expiring within 30 days: 10.4.0.4 10.5.0.1 10.5.0.2",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("needs attention =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(section(body, "Needs attention"), `<a class="more" href="/changes">All changes</a>`) ||
		!strings.Contains(section(body, "Needs attention"), `<a class="addr" href="/hosts/10.5.0.1">`) {
		t.Error("needs attention lacks its links for a viewer")
	}

	rec := do(site.handler, http.MethodGet, "/", nil, &http.Cookie{Name: auth.SessionCookieName, Value: sess.Token})
	body = rec.Body.String()
	if rec.Code != http.StatusOK || strings.Contains(body, "Needs attention") || strings.Contains(body, "10.5.0.") || strings.Contains(body, "10.4.0.4") ||
		!strings.Contains(body, "Your role cannot see inventory data.") {
		t.Errorf("dashboard for a user without inventory.read = %d, want the short message and no attention items\n%s", rec.Code, body)
	}
}

// REQ-WEB-044
func TestDashboardNewAdminPanelsFirst(t *testing.T) {
	site := newInventorySite(t, seedDashboard(t))
	_, body := get(t, site.clients[auth.RoleAdmin], site.url+"/")
	want := []string{
		"New admin panels: 10.4.0.5",
		"New hosts: 10.4.0.5",
		"Services that went missing: 10.4.0.1",
		"Certificates expiring within 30 days: 10.4.0.4",
	}
	if got := attentionOf(body); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("needs attention = %q, want %q", got, want)
	}
}

func TestDashboardChangesHonourConfiguredVolatileHeaders(t *testing.T) {
	ctx := context.Background()
	site := newInventorySite(t, func(ctx context.Context, inv *inventory.Inventory) {
		for i, trace := range []string{"t1", "t2"} {
			run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: fmt.Sprintf("v%d", i+1)})
			if err != nil {
				t.Fatal(err)
			}
			web := inventory.ServiceResult{Port: 80, Protocol: "tcp", State: "open", Service: "http",
				HTTP: &probe.HTTP{Scheme: "http", StatusCode: 200, Title: "Same", Headers: map[string]string{"x-trace-id": trace}}}
			if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: []string{"10.4.1.1"},
				Hosts: []inventory.HostResult{{Address: "10.4.1.1", Services: []inventory.ServiceResult{web}}}}); err != nil {
				t.Fatal(err)
			}
			if err := inv.SetRunStatus(ctx, run.ID, inventory.RunCompleted); err != nil {
				t.Fatal(err)
			}
		}
	})
	changed := func(deps Deps) string {
		h, err := New(deps)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
		req.AddCookie(site.cookies[auth.RoleViewer])
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		panel := section(rec.Body.String(), "Changes in the latest run")
		if strings.Contains(panel, "No changes since run v1.") {
			return "0"
		}
		m := regexp.MustCompile(`<span>Changed services</span><progress class="bar \w+" max="\d+" value="\d+"></progress><span class="num">(\d+)</span>`).FindStringSubmatch(panel)
		if m == nil {
			t.Fatalf("dashboard changes panel (status %d) = %s", rec.Code, panel)
		}
		return m[1]
	}
	if got := changed(site.deps); got != "1" {
		t.Fatalf("control: changed services = %s, want 1 for x-trace-id without configuration", got)
	}
	configured := inventory.New(site.deps.Store, site.deps.Keyring)
	configured.VolatileHeaders = []string{"x-trace-id"}
	deps := site.deps
	deps.Inventory = configured
	if got := changed(deps); got != "0" {
		t.Errorf("changed services = %s with x-trace-id in ASI_VOLATILE_HEADERS, want 0", got)
	}
}

func TestDashboardWithoutInventoryReadShowsOnlyAllowedLinks(t *testing.T) {
	ctx := context.Background()
	site := newInventorySite(t, func(ctx context.Context, inv *inventory.Inventory) {
		run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "audit-run-seven"})
		if err != nil {
			t.Fatal(err)
		}
		host := inventory.HostResult{Address: "10.0.0.1", Services: []inventory.ServiceResult{
			{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"},
			{Port: 80, Protocol: "tcp", State: "open", Service: "http", HTTP: &probe.HTTP{Scheme: "http", Title: "Audit Leak Portal"}},
		}}
		if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.1"}, Hosts: []inventory.HostResult{host}}); err != nil {
			t.Fatal(err)
		}
	})
	svc := site.deps.Auth.(*auth.Service)
	setup := auth.Actor{Username: "test", Addr: "local"}
	base, _ := url.Parse(site.url)
	client := func(role string, perms []auth.Permission) *http.Client {
		if err := svc.CreateRole(ctx, setup, role, perms); err != nil {
			t.Fatalf("CreateRole %s: %v", role, err)
		}
		if err := svc.CreateUser(ctx, setup, role+"-user", role+"-password-123", role); err != nil {
			t.Fatalf("CreateUser %s: %v", role, err)
		}
		sess, err := svc.Login(ctx, role+"-user", role+"-password-123", "local")
		if err != nil {
			t.Fatalf("Login %s: %v", role, err)
		}
		jar, _ := cookiejar.New(nil)
		jar.SetCookies(base, []*http.Cookie{{Name: auth.SessionCookieName, Value: sess.Token, Path: "/"}})
		return &http.Client{Jar: jar}
	}
	href := regexp.MustCompile(`href="([^"]+)"`)
	for _, tc := range []struct {
		role  string
		perms []auth.Permission
		want  []string
	}{
		{"nobody", nil, nil},
		{"exporter", []auth.Permission{auth.PermExport}, []string{"/export"}},
	} {
		c := client(tc.role, tc.perms)
		resp, body := get(t, c, site.url+"/")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s GET / = %d", tc.role, resp.StatusCode)
		}
		checkPageIsSafe(t, "dashboard without inventory.read", body)
		for _, leak := range []string{"10.0.0.1", "Audit Leak Portal", "audit-run-seven", `class="figure"`, "Latest run",
			"Top hosts by interest", "Certificates to check", "Newest admin panels", `href="/hosts`} {
			if strings.Contains(body, leak) {
				t.Errorf("%s dashboard contains %q", tc.role, leak)
			}
		}
		if regexp.MustCompile(`style\s*=`).MatchString(body) {
			t.Errorf("%s dashboard has a style attribute", tc.role)
		}
		i := strings.Index(body, "Your role cannot see inventory data.")
		if i < 0 {
			t.Fatalf("%s dashboard lacks the no-inventory message:\n%s", tc.role, body)
		}
		panel := body[i:]
		panel = panel[:strings.Index(panel, "</section>")]
		var links []string
		for _, m := range href.FindAllStringSubmatch(panel, -1) {
			links = append(links, m[1])
			if resp, _ := get(t, c, site.url+m[1]); resp.StatusCode == http.StatusForbidden || resp.Request.URL.Path != m[1] {
				t.Errorf("%s dashboard links %s, which answers %d at %s", tc.role, m[1], resp.StatusCode, resp.Request.URL.Path)
			}
		}
		for _, w := range tc.want {
			if !slices.Contains(links, w) {
				t.Errorf("%s dashboard links = %v, want %s among them", tc.role, links, w)
			}
		}
		if len(tc.perms) == 0 && len(links) != 0 {
			t.Errorf("zero-permission dashboard links = %v, want none", links)
		}
	}

	resp, body := get(t, site.clients[auth.RoleViewer], site.url+"/")
	if resp.StatusCode != http.StatusOK || strings.Contains(body, "Your role cannot see inventory data.") {
		t.Fatalf("viewer GET / = %d, no-inventory message shown", resp.StatusCode)
	}
	for _, want := range []string{"10.0.0.1", "<dt>Run</dt><dd>audit-run-seven</dd>", `class="figure"`} {
		if !strings.Contains(body, want) {
			t.Errorf("viewer dashboard lacks %q", want)
		}
	}
	if got := figureValue(body, "Active hosts"); got != "1" {
		t.Errorf("viewer active hosts = %q, want 1", got)
	}
	if _, body := get(t, site.clients[auth.RoleAdmin], site.url+"/"); !strings.Contains(body, "10.0.0.1") || strings.Contains(body, "Your role cannot see inventory data.") {
		t.Errorf("admin dashboard lacks inventory data")
	}
}
