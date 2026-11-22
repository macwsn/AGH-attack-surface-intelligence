//go:build integration

package web

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/exchange/defectdojo"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/schedule"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

type dojoAPI struct{ next int }

func (f *dojoAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/engagements/5/":
		fmt.Fprint(w, `{"id": 5, "product": 4}`)
	case r.URL.Path == defectdojo.ImportPath || r.URL.Path == defectdojo.ReimportPath:
		f.next++
		fmt.Fprintf(w, `{"test_id": %d}`, 100+f.next)
	default:
		http.NotFound(w, r)
	}
}

func newAuditEnv(t *testing.T) (*usersEnv, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
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
	runner := &nmaptest.Runner{DiscoverFunc: func(ctx context.Context, _ []string, _ nmap.Options) ([]nmap.Host, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	sched := &schedule.Scheduler{Store: schedule.NewStore(st, keys), Scanner: &scan.Scanner{Store: inv, Runner: runner}, Logf: t.Logf}
	sched.Start(ctx)
	t.Cleanup(func() { cancel(); sched.Wait() })
	dojoSrv := httptest.NewServer(&dojoAPI{})
	t.Cleanup(dojoSrv.Close)
	svc := auth.NewService(st, auth.Config{})
	dojo := &defectdojo.Service{Store: defectdojo.DBStore{DB: st, Keys: keys}, Inventory: inv, HTTP: dojoSrv.Client()}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Users: svc, Roles: svc, Audit: svc, Inventory: inv, Scans: sched,
		DefectDojo: dojo, Signatures: &detect.Set{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e := &usersEnv{h: h, svc: svc, st: st, cookies: map[string]*http.Cookie{}, csrf: map[string]string{}}
	for _, role := range []string{auth.RoleAdmin, auth.RoleEditor, auth.RoleOperator, auth.RoleViewer} {
		e.addSession(t, role, role)
	}
	return e, dojoSrv.URL
}

var auditRowRe = regexp.MustCompile(`<tr><td class="nowrap num">([^<]+)</td><td>([^<]*)</td><td><code>([^<]*)</code></td><td class="wrap addr">([^<]*)</td><td class="addr">([^<]*)</td></tr>`)

func auditPageRows(body string) []string {
	var out []string
	for _, m := range auditRowRe.FindAllStringSubmatch(body, -1) {
		out = append(out, strings.Join(m[2:], " "))
	}
	return out
}

// REQ-WEB-033
func TestAuditPageFiltersAndPages(t *testing.T) {
	e, _ := newAuditEnv(t)
	ctx := context.Background()
	if _, err := e.st.Pool.Exec(ctx, `DELETE FROM audit_log`); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 3, 1, 8, 0, 0, 0, time.Local)
	for i := range 120 {
		actor, action := "olga", "host.edit"
		if i%3 == 0 {
			actor, action = "edna", "import"
		}
		if _, err := e.st.Pool.Exec(ctx, `INSERT INTO audit_log (at, actor, action, target, address) VALUES ($1, $2, $3, $4, '10.1.1.1')`,
			base.Add(time.Duration(i)*time.Hour), actor, action, fmt.Sprintf("t%03d", i)); err != nil {
			t.Fatal(err)
		}
	}

	code, body := e.get(auth.RoleAdmin, "/audit")
	rows := auditPageRows(body)
	if code != http.StatusOK || len(rows) != 50 || rows[0] != "olga host.edit t119 10.1.1.1" || rows[49] != "olga host.edit t070 10.1.1.1" {
		t.Fatalf("page 1 = %d, %d rows, first %q last %q", code, len(rows), first(rows), last(rows))
	}
	for _, want := range []string{"<th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Address</th>", "Showing 1-50 of 120",
		`<span class="num">1 / 3</span>`, `<a class="btn small" href="/audit?page=2" rel="next">Next</a>`,
		`<td class="nowrap num">` + base.Add(119*time.Hour).Format("2006-01-02 15:04:05 MST") + `</td>`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page 1 lacks %q", want)
		}
	}
	checkPageIsSafe(t, "audit page", body)
	if strings.Contains(body, "style=") {
		t.Fatal("audit page has an inline style")
	}
	_, body = e.get(auth.RoleAdmin, "/audit?page=2")
	if rows := auditPageRows(body); len(rows) != 50 || rows[0] != "edna import t069 10.1.1.1" || !strings.Contains(body, "Showing 51-100 of 120") ||
		!strings.Contains(body, `href="/audit" rel="prev"`) || !strings.Contains(body, `href="/audit?page=3" rel="next"`) {
		t.Fatalf("page 2: %d rows, first %q\n%s", len(rows), first(rows), body)
	}

	cases := []struct {
		name, query string
		total       int
		first, last string
	}{
		{"actor", "actor=edna", 40, "edna import t117 10.1.1.1", "edna import t000 10.1.1.1"},
		{"action", "action=host.edit", 80, "olga host.edit t119 10.1.1.1", ""},
		{"target", "target=t005", 1, "olga host.edit t005 10.1.1.1", "olga host.edit t005 10.1.1.1"},
		{"day range", "from=2026-03-02&to=2026-03-02", 24, "edna import t039 10.1.1.1", "olga host.edit t016 10.1.1.1"},
		{"minute range", "from=" + url.QueryEscape("2026-03-01 10:00") + "&to=" + url.QueryEscape("2026-03-01 12:00"), 3,
			"olga host.edit t004 10.1.1.1", "olga host.edit t002 10.1.1.1"},
		{"combined, page 2", "actor=olga&action=host.edit&page=2", 80, "", "olga host.edit t001 10.1.1.1"},
		{"no match", "actor=nobody", 0, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := e.get(auth.RoleAdmin, "/audit?"+tc.query)
			rows := auditPageRows(body)
			if code != http.StatusOK || (tc.first != "" && first(rows) != tc.first) || (tc.last != "" && last(rows) != tc.last) {
				t.Fatalf("%d, rows first %q last %q, want %q %q", code, first(rows), last(rows), tc.first, tc.last)
			}
			if tc.total == 0 {
				if len(rows) != 0 || !strings.Contains(body, "No entries match these filters.") {
					t.Fatalf("no-match page:\n%s", body)
				}
				return
			}
			if !strings.Contains(body, fmt.Sprintf(" of %d</span>", tc.total)) {
				t.Fatalf("total %d not shown:\n%s", tc.total, body)
			}
		})
	}
	if _, body := e.get(auth.RoleAdmin, "/audit?actor=olga&action=host.edit&page=2"); !strings.Contains(body, `href="/audit?action=host.edit&amp;actor=olga" rel="prev"`) {
		t.Fatal("paging links drop the filter")
	}
	if code, body := e.get(auth.RoleAdmin, "/audit?from=yesterday"); code != http.StatusBadRequest || !strings.Contains(body, `From &#34;yesterday&#34; is not a date`) {
		t.Fatalf("bad from = %d", code)
	}
	for _, role := range []string{auth.RoleEditor, auth.RoleOperator, auth.RoleViewer} {
		if code, _ := e.get(role, "/audit"); code != http.StatusForbidden {
			t.Fatalf("%s GET /audit = %d, want 403", role, code)
		}
	}
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func last(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

var runLocation = regexp.MustCompile(`^/runs/(\d+)\?msg=started$`)

// REQ-WEB-034
func TestEveryWebChangeIsAudited(t *testing.T) {
	e, dojoURL := newAuditEnv(t)
	ctx := context.Background()
	upload := func(fields map[string]string, file string) *httptest.ResponseRecorder {
		req := uploadRequest(t, fields, "hosts.json", []byte(file))
		req.Header.Set(auth.CSRFHeader, e.csrf[auth.RoleAdmin])
		req.AddCookie(e.cookies[auth.RoleAdmin])
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}
	sig := strings.ReplaceAll(signatureTemplate, "admin-panel-login", "audit-test-sig")
	scanForm := url.Values{"name": {"campus"}, "targets": {"10.0.0.0/30"}, "excludes": {""}, "ports": {"80"}, "max_rate": {"50"},
		"workers": {"1"}, "inactive_after": {"3"}, "signatures_dir": {""}, "timezone": {"UTC"}, "windows": {""}, "frequency": {"daily"}}
	var runURL, runName string
	steps := []struct {
		name, action, target string
		do                   func() (int, string)
	}{
		{"UI import", "import", "upload-a", func() (int, string) {
			rec := upload(map[string]string{"format": "json", "name": "upload-a"}, twoHosts)
			return rec.Code, rec.Body.String()
		}},
		{"UI import dry run writes nothing", "", "", func() (int, string) {
			rec := upload(map[string]string{"format": "json", "name": "upload-dry", "dry_run": "1"}, twoHosts)
			return rec.Code, rec.Body.String()
		}},
		{"manual entry", "host.entry", "10.0.0.9", func() (int, string) {
			code, _, body := e.post(auth.RoleAdmin, "/hosts/entry", url.Values{"address": {"10.0.0.9"}, "port": {"22"}, "service": {"ssh"}})
			return code, body
		}},
		{"host edit", "host.edit", "10.0.0.9", func() (int, string) {
			code, _, body := e.post(auth.RoleAdmin, "/hosts/10.0.0.9", url.Values{"tags": {"dmz"}, "criticality": {"high"}})
			return code, body
		}},
		{"signature create", "signature.create", "audit-test-sig", func() (int, string) {
			code, _, body := e.post(auth.RoleAdmin, "/signatures", url.Values{"source": {sig}, "enabled": {"1"}})
			return code, body
		}},
		{"signature update", "signature.update", "audit-test-sig", func() (int, string) {
			code, _, body := e.post(auth.RoleAdmin, "/signatures/audit-test-sig", url.Values{"source": {strings.ReplaceAll(sig, "confidence: 80", "confidence: 70")}, "enabled": {"1"}})
			return code, body
		}},
		{"signature delete", "signature.delete", "audit-test-sig", func() (int, string) {
			code, _, body := e.post(auth.RoleAdmin, "/signatures/audit-test-sig/delete", url.Values{})
			return code, body
		}},
		{"scan create", "scan.create", "campus", func() (int, string) {
			code, _, body := e.post(auth.RoleAdmin, "/scans", scanForm)
			return code, body
		}},
		{"scan start", "scan.start", "", func() (int, string) {
			var id int64
			if err := e.st.Pool.QueryRow(ctx, `SELECT id FROM scan_definitions WHERE name = 'campus'`).Scan(&id); err != nil {
				t.Fatal(err)
			}
			code, loc, body := e.post(auth.RoleAdmin, fmt.Sprintf("/scans/%d/start", id), url.Values{})
			m := runLocation.FindStringSubmatch(loc)
			if m == nil {
				return code, "start redirected to " + loc + "\n" + body
			}
			runURL = "/runs/" + m[1]
			if err := e.st.Pool.QueryRow(ctx, `SELECT name FROM runs WHERE id = $1`, m[1]).Scan(&runName); err != nil {
				t.Fatal(err)
			}
			return code, body
		}},
		{"scan pause", "scan.pause", "", func() (int, string) {
			code, _, body := e.post(auth.RoleAdmin, runURL+"/pause", url.Values{})
			return code, body
		}},
		{"scan resume", "scan.resume", "", func() (int, string) {
			code, _, body := e.post(auth.RoleAdmin, runURL+"/resume", url.Values{})
			return code, body
		}},
		{"defectdojo configure", "defectdojo.configure", "", func() (int, string) {
			code, _, body := e.post(auth.RoleAdmin, "/defectdojo/settings", url.Values{"base_url": {dojoURL}, "token": {"dojo-token-123"},
				"product_id": {"4"}, "engagement_id": {"5"}})
			return code, body
		}},
		{"defectdojo export", "defectdojo.export", "upload-a", func() (int, string) {
			code, _, body := e.post(auth.RoleAdmin, "/defectdojo/export", url.Values{"run": {"upload-a"}})
			return code, body
		}},
	}
	for _, s := range steps {
		mark := e.lastAudit(t)
		code, body := s.do()
		if code >= 400 {
			t.Fatalf("%s: %d\n%.600s", s.name, code, body)
		}
		got := e.auditAfter(t, mark)
		if s.action == "" {
			if len(got) != 0 {
				t.Fatalf("%s: audit rows %q, want none", s.name, got)
			}
			continue
		}
		target := s.target
		switch {
		case strings.HasPrefix(s.action, "scan.") && s.action != "scan.create":
			target = runName
		case s.action == "defectdojo.configure":
			target = dojoURL
		}
		want := "admin " + s.action + " " + target + " 192.0.2.1"
		if len(got) != 1 || got[0] != want {
			t.Fatalf("%s: audit rows %q, want exactly %q", s.name, got, want)
		}
	}
	if runName == "" {
		t.Fatal("no run was started")
	}
}
