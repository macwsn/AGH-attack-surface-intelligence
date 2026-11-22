//go:build integration

package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/diff"
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

func signInClient(t *testing.T, srv *httptest.Server, username, password string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	_, body := get(t, c, srv.URL+"/login")
	m := csrfInput.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("login form has no CSRF token")
	}
	resp, err := c.PostForm(srv.URL+"/login", url.Values{"username": {username}, "password": {password}, "csrf_token": {m[1]}})
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path != "/" {
		t.Fatalf("login ended at %s", resp.Request.URL)
	}
	return c
}

var changeRowRE = regexp.MustCompile(`<tr data-type="([a-z_]+)"><td><span class="change [a-z]+">[^<]+</span></td><td><a class="addr" href="/hosts/([^/"]+)/timeline">([^<]+)</a></td><td class="addr">([^<]*)</td>`)

func changeRows(body string) []string {
	var rows []string
	for _, m := range changeRowRE.FindAllStringSubmatch(body, -1) {
		if m[2] != m[3] {
			rows = append(rows, "bad link "+m[2]+" for "+m[3])
			continue
		}
		rows = append(rows, m[1]+" "+m[3]+" "+m[4])
	}
	return rows
}

func diffRows(d diff.Diff, typ string) []string {
	var rows []string
	for _, c := range d.Changes {
		if typ != "" && c.Type != typ {
			continue
		}
		svc := ""
		if c.Port != nil {
			svc = fmt.Sprintf("%d/%s", *c.Port, c.Protocol)
		}
		rows = append(rows, c.Type+" "+c.Address+" "+svc)
	}
	return rows
}

// REQ-WEB-010 REQ-WEB-012
func TestChangesPageWithRecordedRuns(t *testing.T) {
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
		t.Fatal(err)
	}
	inv := inventory.New(st, keys)
	svc := auth.NewService(st, auth.Config{})
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, "vera", "vera-password-123", auth.RoleViewer); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := signInClient(t, srv, "vera", "vera-password-123")

	resp, body := get(t, c, srv.URL+"/changes")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Changes appear here once two scan runs have completed.") {
		t.Fatalf("/changes without runs = %d:\n%s", resp.StatusCode, body)
	}

	addrs := []string{"10.9.0.1", "10.9.0.2", "10.9.0.3"}
	host := func(addr, title string) inventory.HostResult {
		return inventory.HostResult{Address: addr, Services: []inventory.ServiceResult{{Port: 80, Protocol: "tcp", State: "open",
			HTTP: &probe.HTTP{StatusCode: 200, Title: title}}}}
	}
	record := func(name string, hosts ...inventory.HostResult) {
		r, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name, InactiveAfter: 3})
		if err != nil {
			t.Fatalf("CreateRun %s: %v", name, err)
		}
		if err := inv.RecordGroup(ctx, r.ID, inventory.GroupResult{Addresses: addrs, Hosts: hosts}); err != nil {
			t.Fatalf("RecordGroup %s: %v", name, err)
		}
		if err := inv.SetRunStatus(ctx, r.ID, inventory.RunCompleted); err != nil {
			t.Fatal(err)
		}
	}
	record("w1", host("10.9.0.1", "Intranet v1"), host("10.9.0.2", "ok"))
	record("w2", host("10.9.0.1", "Intranet v2"), host("10.9.0.3", "<script>alert(1)</script>"))
	record("w3", host("10.9.0.1", "Intranet v3"), host("10.9.0.2", "ok"), host("10.9.0.3", "x"))

	check := func(query, from, to, typ string) {
		t.Helper()
		resp, body := get(t, c, srv.URL+"/changes"+query)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/changes%s = %d:\n%s", query, resp.StatusCode, body)
		}
		for _, want := range []string{`<option value="` + from + `" selected>`, `<option value="` + to + `" selected>`} {
			if strings.Count(body, want) != 1 {
				t.Errorf("/changes%s: want one %s:\n%s", query, want, body)
			}
		}
		if strings.Contains(body, "<script>alert") {
			t.Errorf("/changes%s is not escaped", query)
		}
		d, err := diff.Between(ctx, inv, from, to, diff.Options{})
		if err != nil {
			t.Fatal(err)
		}
		got, want := changeRows(body), diffRows(d, typ)
		if len(want) == 0 || strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("/changes%s rows:\n%s\nwant (diff %s..%s):\n%s", query, strings.Join(got, "\n"), from, to, strings.Join(want, "\n"))
		}
		if n := strings.Count(body, "<tr data-type="); n != len(want) {
			t.Errorf("/changes%s: %d rows, want %d", query, n, len(want))
		}
	}
	check("", "w2", "w3", "")
	check("?from=w1&to=w3", "w1", "w3", "")
	check("?from=w1&to=w2", "w1", "w2", "")
	check("?from=w1&to=w2&type=service_changed", "w1", "w2", diff.ServiceChanged)
	check("?type=host_returned", "w2", "w3", diff.HostReturned)

	resp, body = get(t, c, srv.URL+"/changes?from=w1&to=nope")
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Run &#34;nope&#34; does not exist.") {
		t.Errorf("unknown run = %d:\n%s", resp.StatusCode, body)
	}
	resp, body = get(t, c, srv.URL+"/changes?type=bogus")
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Unknown change type") {
		t.Errorf("unknown type = %d:\n%s", resp.StatusCode, body)
	}
}

// REQ-WEB-013
func TestTimelinePageWithRecordedRuns(t *testing.T) {
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
		t.Fatal(err)
	}
	inv := inventory.New(st, keys)
	svc := auth.NewService(st, auth.Config{})
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, "vera", "vera-password-123", auth.RoleViewer); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Inventory: inv})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := signInClient(t, srv, "vera", "vera-password-123")

	const host, office = "10.8.0.5", "10.8.0.9"
	svcWith := func(title string, findings ...inventory.Finding) inventory.HostResult {
		return inventory.HostResult{Address: host, Services: []inventory.ServiceResult{{Port: 80, Protocol: "tcp", State: "open",
			HTTP: &probe.HTTP{StatusCode: 200, Title: title}, Findings: findings}}}
	}
	day := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	plan := []struct {
		covered    []string
		hosts      []inventory.HostResult
		officeHour int
	}{
		{[]string{host, office}, []inventory.HostResult{svcWith("Intranet v1"), {Address: office}}, 9},
		{[]string{host, office}, nil, 22},
		{[]string{office}, []inventory.HostResult{{Address: office}}, 11},
		{[]string{host, office}, []inventory.HostResult{svcWith("Intranet <v2>", inventory.Finding{SignatureID: "admin-panel-login", Kind: "admin-panel"})}, 3},
		{[]string{office}, []inventory.HostResult{{Address: office}}, 15},
		{[]string{office}, nil, 19},
		{[]string{office}, []inventory.HostResult{{Address: office}}, 8},
	}
	for i, p := range plan {
		r, err := inv.CreateRun(ctx, inventory.RunSpec{Name: fmt.Sprintf("tl-%d", i+1), InactiveAfter: 3})
		if err != nil {
			t.Fatal(err)
		}
		if err := inv.RecordGroup(ctx, r.ID, inventory.GroupResult{Addresses: p.covered, Hosts: p.hosts}); err != nil {
			t.Fatal(err)
		}
		at := day.AddDate(0, 0, i).Add(time.Duration(p.officeHour)*time.Hour + 10*time.Minute)
		if _, err := st.Pool.Exec(ctx, `UPDATE run_groups SET completed_at = $2 WHERE run_id = $1`, r.ID, at); err != nil {
			t.Fatal(err)
		}
	}

	resp, body := get(t, c, srv.URL+"/hosts/"+host+"/timeline")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("timeline = %d:\n%s", resp.StatusCode, body)
	}
	cells := regexp.MustCompile(`<rect class="([a-z]+)" x="[0-9.]+" y="0.5" width="7" height="15"><title>(tl-\d+),`).FindAllStringSubmatch(body, -1)
	var got []string
	for _, m := range cells {
		got = append(got, m[2]+"="+m[1])
	}
	want := "tl-1=seen,tl-2=missed,tl-3=uncovered,tl-4=seen,tl-5=uncovered,tl-6=uncovered,tl-7=uncovered"
	if strings.Join(got, ",") != want {
		t.Errorf("strip = %v, want %s", got, want)
	}
	row := regexp.MustCompile(`(?s)<tr data-run="tl-4">.*?</tr>`).FindString(body)
	if !strings.Contains(row, `<div data-type="service_changed"><span class="change changed">Changed service</span> <span class="addr">80/tcp</span>`) ||
		!strings.Contains(row, `http.title <del>Intranet v1</del> <ins>Intranet &lt;v2&gt;</ins>`) {
		t.Errorf("tl-4 row lacks the title change: %s", row)
	}
	if regexp.MustCompile(`<script[^>]*src="[^/]|<link[^>]*href="[^/]|style=|<style`).MatchString(body) {
		t.Errorf("page references external assets or inline styles")
	}

	tl, err := inv.HostTimeline(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	score, reasons := inventory.Score(tl.Host, tl.LatestAt, nil)
	if !strings.Contains(body, fmt.Sprintf(`<progress max="100" value="%d"></progress>%d</span>`, score, score)) || len(reasons) == 0 {
		t.Errorf("page lacks score %d", score)
	}
	for _, r := range reasons {
		if !strings.Contains(body, fmt.Sprintf(`<tr data-reason="%s"><td>%s</td><td class="num">%d</td></tr>`, r.Code, r.Label, r.Points)) {
			t.Errorf("page lacks reason %+v", r)
		}
	}
	if n := strings.Count(body, "<tr data-reason="); n != len(reasons) {
		t.Errorf("page lists %d reasons, want %d", n, len(reasons))
	}

	_, body = get(t, c, srv.URL+"/hosts/"+office+"/timeline")
	if !strings.Contains(body, `<span class="muted">Usually seen 08:00-16:00</span>`) || strings.Contains(body, "Unstable") {
		t.Errorf("office host does not show usual hours:\n%s", body)
	}
	for target, status := range map[string]int{"/hosts/10.8.0.77/timeline": http.StatusNotFound, "/hosts/not-an-ip/timeline": http.StatusBadRequest} {
		if resp, _ := get(t, c, srv.URL+target); resp.StatusCode != status {
			t.Errorf("%s = %d, want %d", target, resp.StatusCode, status)
		}
	}
}

// REQ-WEB-014 REQ-WEB-015
func TestGroupsAndDashboardChartWithRecordedRuns(t *testing.T) {
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
		t.Fatal(err)
	}
	inv := inventory.New(st, keys)
	svc := auth.NewService(st, auth.Config{})
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, "vera", "vera-password-123", auth.RoleViewer); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Inventory: inv})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := signInClient(t, srv, "vera", "vera-password-123")

	resp, body := get(t, c, srv.URL+"/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "A chart of changes per run appears here once two scan runs have completed.") {
		t.Fatalf("dashboard without runs = %d:\n%s", resp.StatusCode, body)
	}

	addrs := []string{"10.7.0.1", "10.7.0.2", "10.7.0.3", "10.7.0.4", "10.7.0.5"}
	login := func(addr string, port int, title, favicon string, techs ...string) inventory.HostResult {
		s := inventory.ServiceResult{Port: port, Protocol: "tcp", State: "open", HTTP: &probe.HTTP{StatusCode: 200, Title: title, FaviconSHA256: favicon}}
		for _, name := range techs {
			s.Technologies = append(s.Technologies, inventory.Technology{Name: name, Category: "web", Confidence: 90, Source: "builtin"})
		}
		return inventory.HostResult{Address: addr, Services: []inventory.ServiceResult{s}}
	}
	var names []string
	for i := 0; i < 22; i++ {
		hosts := []inventory.HostResult{
			login("10.7.0.1", 80, "Login", "aa", "nginx", "PHP"),
			login("10.7.0.2", 443, "Login", "aa", "PHP", "nginx"),
			login("10.7.0.3", 8080, "Login", "aa", "nginx", "PHP"),
			login("10.7.0.4", 80, "Login", "bb", "nginx", "PHP"),
		}
		if i%3 != 0 {
			hosts = append(hosts, login("10.7.0.5", 80, fmt.Sprintf("Build %d", i/2), "cc"))
		}
		name := fmt.Sprintf("g%02d", i)
		r, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name, InactiveAfter: 2})
		if err != nil {
			t.Fatal(err)
		}
		if err := inv.RecordGroup(ctx, r.ID, inventory.GroupResult{Addresses: addrs, Hosts: hosts}); err != nil {
			t.Fatal(err)
		}
		if err := inv.SetRunStatus(ctx, r.ID, inventory.RunCompleted); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}

	_, body = get(t, c, srv.URL+"/")
	m := regexp.MustCompile(`<g data-run="([^"]+)" data-new="(\d+)" data-missing="(\d+)" data-changed="(\d+)">`).FindAllStringSubmatch(body, -1)
	if len(m) != 20 {
		t.Fatalf("chart has %d entries, want 20:\n%s", len(m), body)
	}
	nonzero := 0
	for i, e := range m {
		from, to := names[i+1], names[i+2]
		if e[1] != to {
			t.Errorf("entry %d is run %s, want %s", i, e[1], to)
		}
		d, err := diff.Between(ctx, inv, from, to, diff.Options{})
		if err != nil {
			t.Fatal(err)
		}
		want := diff.Count(d)
		if got := fmt.Sprintf("%s/%s/%s", e[2], e[3], e[4]); got != fmt.Sprintf("%d/%d/%d", want.New, want.Missing, want.Changed) {
			t.Errorf("%s..%s counts %s, want %+v", from, to, got, want)
		}
		nonzero += want.New + want.Missing + want.Changed
	}
	if nonzero == 0 {
		t.Error("synthetic runs produced no changes at all")
	}

	resp, body = get(t, c, srv.URL+"/groups")
	counts := regexp.MustCompile(`<tr data-count="(\d+)"><td class="num">\d+</td><td>([^<]*)</td><td>([^<]*)</td><td class="addr">([^<]*)</td>`).FindAllStringSubmatch(body, -1)
	if resp.StatusCode != http.StatusOK || len(counts) < 2 || counts[0][1] != "3" || counts[0][2] != "PHP, nginx" || counts[0][4] != "aa" ||
		counts[1][1] != "1" || counts[1][4] != "bb" {
		t.Fatalf("groups = %v:\n%s", counts, body)
	}
	for _, a := range []string{"10.7.0.1", "10.7.0.2", "10.7.0.3"} {
		if !strings.Contains(body, `href="/hosts/`+a+`/timeline"`) {
			t.Errorf("groups page lacks a link to %s", a)
		}
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
	lib := detect.NewLibrary(st, keys, "")
	enabledIDs := func() []string {
		t.Helper()
		sigs, err := lib.Enabled(ctx)
		if err != nil {
			t.Fatalf("Enabled: %v", err)
		}
		var ids []string
		for _, s := range sigs {
			if strings.HasPrefix(s.ID, detect.PackIDPrefix) {
				continue
			}
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

type failOnUse struct{ used *bool }

func (f failOnUse) RoundTrip(*http.Request) (*http.Response, error) {
	*f.used = true
	return nil, errors.New("network use during a hunt")
}

// REQ-SIGNATURES-009 REQ-SIGNATURES-010 REQ-SIGNATURES-011
func TestSignatureHuntWithRealStore(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	keys, err := store.NewKeyring(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(st, auth.Config{})
	login := func(user, role string) (*http.Cookie, string) {
		t.Helper()
		if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, user, user+"-password-123", role); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		sess, err := svc.Login(ctx, user, user+"-password-123", "")
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		return &http.Cookie{Name: auth.SessionCookieName, Value: sess.Token}, sess.CSRFToken
	}
	cookie, csrf := login("eddie", auth.RoleEditor)
	viewer, viewerCSRF := login("vera", auth.RoleViewer)

	used := false
	prev := http.DefaultTransport
	http.DefaultTransport = failOnUse{used: &used}
	t.Cleanup(func() { http.DefaultTransport = prev })

	inv := inventory.New(st, keys)
	record := func(name string, title func(i int) string) {
		t.Helper()
		run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		g := inventory.GroupResult{Index: 0}
		for i := 1; i <= 70; i++ {
			addr := fmt.Sprintf("10.0.1.%d", i)
			g.Addresses = append(g.Addresses, addr)
			g.Hosts = append(g.Hosts, inventory.HostResult{Address: addr, Services: []inventory.ServiceResult{{Port: 80, Protocol: "tcp", State: "open", Service: "http",
				HTTP: &probe.HTTP{Scheme: "http", URL: "http://" + addr + "/", StatusCode: 200, Title: title(i), Headers: map[string]string{}},
				Body: []byte("<p>Jenkins ver. 2." + strconv.Itoa(i) + "</p>")}}})
		}
		if err := inv.RecordGroup(ctx, run.ID, g); err != nil {
			t.Fatalf("RecordGroup: %v", err)
		}
	}
	record("w1", func(i int) string { return "Jenkins" })
	record("w2", func(i int) string {
		if i <= 55 {
			return "Jenkins"
		}
		return "Moved"
	})

	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	post := func(path string, v url.Values) *httptest.ResponseRecorder {
		t.Helper()
		v.Set(auth.CSRFFormField, csrf)
		return do(h, http.MethodPost, path, v, cookie)
	}
	want := func(what string, rec *httptest.ResponseRecorder, status int, texts ...string) {
		t.Helper()
		for _, text := range texts {
			if rec.Code != status || !strings.Contains(rec.Body.String()+rec.Header().Get("Location"), text) {
				t.Fatalf("%s = %d (Location %q), want %d containing %q:\n%s", what, rec.Code, rec.Header().Get("Location"), status, text, rec.Body)
			}
		}
	}
	jenkins := "id: jenkins\nname: Jenkins\nkind: technology\nconfidence: 90\nmatch:\n  all:\n    - {type: title_regex, value: Jenkins}\n    - {type: body_regex, value: 'Jenkins ver'}\nversion: {type: body_regex, value: 'ver\\. ([0-9.]+)', group: 1}\n"

	want("form has the action", do(h, http.MethodGet, "/signatures/new", nil, cookie), http.StatusOK, `formaction="/signatures/hunt"`, "Hunt in history")
	rec := post("/signatures/hunt", url.Values{"source": {jenkins}, "since": {"30d"}})
	want("hunt", rec, http.StatusSeeOther, "/signatures/hunts/")
	page := rec.Header().Get("Location")
	want("results", do(h, http.MethodGet, page, nil, cookie), http.StatusOK,
		"Hunt for <code>jenkins</code>", "Showing 1-50 of 70", "1 / 2", "No request was sent.", `<td class="addr">10.0.1.1</td>`,
		`<span class="status active">Matches now</span>`, "<code>2.1</code>", `href="`+page+`?page=2"`)
	want("page 2", do(h, http.MethodGet, page+"?page=2", nil, cookie), http.StatusOK, "Showing 51-70 of 70", "Matched before", `<td class="addr">10.0.1.70</td>`)
	want("unknown hunt", do(h, http.MethodGet, "/signatures/hunts/999999", nil, cookie), http.StatusNotFound, "does not exist")
	want("invalid draft", post("/signatures/hunt", url.Values{"source": {strings.Replace(jenkins, "match:", "request: {method: PUT}\nmatch:", 1)}}),
		http.StatusUnprocessableEntity, "Rule violated: "+detect.RuleMethod)
	want("not evaluable", do(h, http.MethodGet, post("/signatures/hunt", url.Values{"source": {strings.Replace(jenkins, "match:", "request: {path: /login}\nmatch:", 1)}}).Header().Get("Location"), nil, cookie),
		http.StatusOK, "Not evaluable from history", "Showing 1-50 of 70")

	csvRec := do(h, http.MethodGet, page+"/csv", nil, cookie)
	if csvRec.Code != http.StatusOK || !strings.HasPrefix(csvRec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("csv = %d %s", csvRec.Code, csvRec.Header().Get("Content-Type"))
	}
	lines := strings.Split(strings.TrimSpace(csvRec.Body.String()), "\n")
	if len(lines) != 71 || lines[0] != "address,port,protocol,evaluable,first_run,last_run,matches_latest_run,version" || lines[1] != "10.0.1.1,80,tcp,true,w1,w2,true,2.1" || lines[70] != "10.0.1.70,80,tcp,true,w1,w1,false,2.70" {
		t.Fatalf("csv:\n%s", csvRec.Body)
	}

	want("viewer cannot hunt", func() *httptest.ResponseRecorder {
		return do(h, http.MethodPost, "/signatures/hunt", url.Values{"source": {jenkins}, auth.CSRFFormField: {viewerCSRF}}, viewer)
	}(), http.StatusForbidden, "")
	want("viewer cannot read a hunt", do(h, http.MethodGet, page, nil, viewer), http.StatusForbidden, "")

	want("save and record", post(page+"/save", url.Values{"record": {"1"}}), http.StatusSeeOther, page+"?saved=1&recorded=55")
	want("saved", do(h, http.MethodGet, page+"?saved=1&recorded=55", nil, cookie), http.StatusOK, "Signature jenkins saved. Recorded 55 findings in run w2.")
	if s, err := detect.NewLibrary(st, keys, "").Get(ctx, "jenkins"); err != nil || !s.Enabled || s.Source != jenkins {
		t.Fatalf("stored signature = %+v, %v", s, err)
	}
	exp, err := inv.Export(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	findings := 0
	for _, eh := range exp.Hosts {
		for _, es := range eh.Services {
			for _, f := range es.Findings {
				if f.SignatureID == "jenkins" && f.Source == inventory.SourceRetroHunt {
					findings++
				}
			}
		}
	}
	if findings != 55 {
		t.Fatalf("export of the latest run has %d retro-hunt findings, want 55", findings)
	}
	if used {
		t.Fatal("a hunt page used the network")
	}

	rows, err := st.Pool.Query(ctx, `SELECT actor || ' ' || action || ' ' || target FROM audit_log WHERE action LIKE 'signature.%' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	wantAudit := []string{"eddie signature.hunt jenkins", "eddie signature.hunt jenkins", "eddie signature.create jenkins", "eddie signature.hunt.record jenkins"}
	if strings.Join(got, "\n") != strings.Join(wantAudit, "\n") {
		t.Fatalf("audit log:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantAudit, "\n"))
	}
}

// REQ-SIGNATURES-009
func TestHuntCSVNeutralizesFormulas(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	keys, err := store.NewKeyring(bytes.Repeat([]byte{5}, 32))
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

	inv := inventory.New(st, keys)
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "@run"})
	if err != nil {
		t.Fatal(err)
	}
	title := `=HYPERLINK("http://evil.example","Jenkins")`
	g := inventory.GroupResult{Index: 0, Addresses: []string{"10.0.2.1"}, Hosts: []inventory.HostResult{{Address: "10.0.2.1", Services: []inventory.ServiceResult{{
		Port: 80, Protocol: "tcp", State: "open", Service: "http",
		HTTP: &probe.HTTP{Scheme: "http", URL: "http://10.0.2.1/", StatusCode: 200, Title: title, Headers: map[string]string{}}}}}}}
	if err := inv.RecordGroup(ctx, run.ID, g); err != nil {
		t.Fatalf("RecordGroup: %v", err)
	}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	src := "id: title-hunt\nname: Title\nkind: technology\nconfidence: 90\nmatch:\n  all:\n    - {type: title_regex, value: Jenkins}\nversion: {type: title_regex, value: '^(.*)$', group: 1}\n"
	rec := do(h, http.MethodPost, "/signatures/hunt", url.Values{"source": {src}, auth.CSRFFormField: {sess.CSRFToken}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("hunt = %d:\n%s", rec.Code, rec.Body)
	}
	csvRec := do(h, http.MethodGet, rec.Header().Get("Location")+"/csv", nil, cookie)
	rows, err := csv.NewReader(csvRec.Body).ReadAll()
	if csvRec.Code != http.StatusOK || err != nil || len(rows) != 2 {
		t.Fatalf("csv = %d %v:\n%v", csvRec.Code, err, rows)
	}
	if want := []string{"10.0.2.1", "80", "tcp", "true", "'@run", "'@run", "true", "'" + title}; !slices.Equal(rows[1], want) {
		t.Fatalf("csv row = %q, want %q", rows[1], want)
	}
}
