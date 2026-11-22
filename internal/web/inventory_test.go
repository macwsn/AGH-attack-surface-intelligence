package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/probe"
)

// REQ-WEB-020
func TestHostFilterRoundTrip(t *testing.T) {
	in := url.Values{"q": {" portal "}, "status": {"active"}, "port": {"443"}, "service": {"http"}, "technology": {"nginx"},
		"finding": {"admin-panel"}, "tag": {"dmz"}, "sort": {"interest"}, "dir": {"desc"}, "page": {"3"}}
	f, problem := parseHostFilter(in)
	if problem != "" {
		t.Fatalf("parseHostFilter: %s", problem)
	}
	q := f.query()
	want := inventory.HostQuery{Status: "active", Port: 443, Service: "http", Technology: "nginx", FindingKind: "admin-panel",
		Tag: "dmz", Text: "portal", Sort: "interest", Desc: true, Page: 3, PerPage: inventory.DefaultPerPage}
	if q != want {
		t.Errorf("query = %+v, want %+v", q, want)
	}
	u, err := url.Parse(f.url())
	if err != nil || u.Path != "/hosts/" {
		t.Fatalf("url = %q, %v", f.url(), err)
	}
	back, _ := parseHostFilter(u.Query())
	if back != f {
		t.Errorf("round trip = %+v, want %+v", back, f)
	}
	if got := (hostFilter{Page: 1}).url(); got != "/hosts/" {
		t.Errorf("empty filter url = %q", got)
	}
}

// REQ-WEB-020
func TestHostFilterRejectsBadValues(t *testing.T) {
	for _, raw := range []string{"status=gone", "status=active'--", "port=abc", "port=0", "port=70000",
		"sort=address%3Bdrop", "sort=interest_score", "page=0", "page=-1", "page=x"} {
		v, _ := url.ParseQuery(raw)
		if _, problem := parseHostFilter(v); problem == "" {
			t.Errorf("parseHostFilter(%s) accepted", raw)
		}
	}
}

// REQ-WEB-020
func TestHostsViewLinksKeepFilters(t *testing.T) {
	f := hostFilter{Status: "active", Tag: "dmz", Sort: "interest", Desc: true, Page: 2}
	now := time.Now()
	p := inventory.HostPage{Total: 120, Page: 2, PerPage: 50, Hosts: []inventory.HostRow{
		{Address: "10.0.0.1", Status: inventory.StatusActive, InterestScore: 80, Ports: []int{80, 443},
			FindingKinds: []string{"admin-panel"}, LastSeen: now.Add(-5 * time.Minute)},
	}}
	v := newHostsView(f, p, now)
	for name, link := range map[string]string{"prev": v.PrevURL, "next": v.NextURL} {
		u, _ := url.Parse(link)
		q := u.Query()
		if q.Get("status") != "active" || q.Get("tag") != "dmz" || q.Get("sort") != "interest" || q.Get("dir") != "desc" {
			t.Errorf("%s link %q drops the filter", name, link)
		}
	}
	if u, _ := url.Parse(v.PrevURL); u.Query().Get("page") != "" {
		t.Errorf("prev link of page 2 = %q, want the first page", v.PrevURL)
	}
	if u, _ := url.Parse(v.NextURL); u.Query().Get("page") != "3" {
		t.Errorf("next link = %q, want page 3", v.NextURL)
	}
	if v.From != "51" || v.To != "51" || v.Pages != 3 || v.Total != "120" {
		t.Errorf("counts = %s-%s of %s, %d pages", v.From, v.To, v.Total, v.Pages)
	}
	for _, c := range v.Columns {
		u, _ := url.Parse(c.URL)
		q := u.Query()
		if q.Get("status") != "active" || q.Get("tag") != "dmz" || q.Get("page") != "" {
			t.Errorf("column %s link %q", c.Label, c.URL)
		}
		if c.Label == "Interest" && (c.AriaSort != "descending" || q.Get("dir") != "") {
			t.Errorf("interest column = %+v, want descending with a link that flips to ascending", c)
		}
		if c.Label != "Interest" && c.AriaSort != "" {
			t.Errorf("column %s marked sorted", c.Label)
		}
	}
	row := v.Rows[0]
	if row.URL != "/hosts/10.0.0.1" || row.Ports != "80, 443" || !row.InterestHigh || row.LastSeen != "5 minutes ago" ||
		len(row.Kinds) != 1 || row.Kinds[0].Label != "Admin panel" {
		t.Errorf("row = %+v", row)
	}
	last := newHostsView(hostFilter{Page: 3}, inventory.HostPage{Total: 120, Page: 3, PerPage: 50}, now)
	if last.NextURL != "" || last.PrevURL == "" {
		t.Errorf("last page links = prev %q next %q", last.PrevURL, last.NextURL)
	}
}

func TestCount(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1284: "1 284", 20000: "20 000", 1234567: "1 234 567"} {
		if got := count(n); got != want {
			t.Errorf("count(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestCertExpiry(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	if got := certExpiry("2026-12-01T12:00:00Z", now); !strings.HasSuffix(got, "expires in 10 days") {
		t.Errorf("soon = %q", got)
	}
	if got := certExpiry("2026-01-01T00:00:00Z", now); !strings.HasSuffix(got, "expired") {
		t.Errorf("past = %q", got)
	}
	if got := certExpiry("2028-01-01T00:00:00Z", now); strings.Contains(got, "expire") {
		t.Errorf("far = %q", got)
	}
}

// REQ-WEB-020
func TestHostsRoutes(t *testing.T) {
	r, fa := newTestRouter(t)
	viewer := fa.session(t, "victor")
	rec := do(r, http.MethodGet, "/hosts", nil, viewer)
	if rec.Code/100 != 3 || rec.Header().Get("Location") != "/hosts/" {
		t.Errorf("GET /hosts = %d %q, want a redirect to /hosts/", rec.Code, rec.Header().Get("Location"))
	}
	for _, target := range []string{"/hosts/?status=bogus", "/hosts/?port=x", "/hosts/?sort=nope", "/hosts/?page=0"} {
		rec := do(r, http.MethodGet, target, nil, viewer)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "400 Bad Request") {
			t.Errorf("GET %s = %d, want the 400 error page", target, rec.Code)
		}
	}
	body := do(r, http.MethodGet, "/", nil, viewer).Body.String()
	if !strings.Contains(body, `<a href="/hosts/">Hosts</a>`) {
		t.Errorf("viewer navigation lacks Hosts")
	}
}

// REQ-WEB-022
func TestParseHostForm(t *testing.T) {
	form := func(kv ...string) *http.Request {
		v := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		req := httptest.NewRequest(http.MethodPost, "/hosts/10.0.0.1", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}
	f := parseHostForm(form("tags", " a, b ,a,, c ", "display_name", "  Name ", "owner", "Team", "criticality", "critical",
		"status_override", "unstable", "notes", " text "))
	if len(f.Problems) != 0 {
		t.Fatalf("problems = %v", f.Problems)
	}
	got := f.fields()
	want := inventory.HostUserFields{Tags: []string{"a", "b", "c"}, DisplayName: "Name", Owner: "Team", Criticality: "critical",
		StatusOverride: "unstable", Notes: "text"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fields = %+v, want %+v", got, want)
	}
	if empty := parseHostForm(form()); len(empty.Problems) != 0 || empty.fields().Tags != nil {
		t.Errorf("empty form = %+v", empty)
	}
	for field, value := range map[string]string{
		"tags": strings.Repeat("x", 65), "display_name": strings.Repeat("é", 201), "owner": strings.Repeat("o", 201),
		"criticality": "urgent", "status_override": "gone", "notes": strings.Repeat("n", 10001),
	} {
		if f := parseHostForm(form(field, value)); f.Problems[field] == "" || len(f.Problems) != 1 {
			t.Errorf("%s=%.20q: problems %v", field, value, f.Problems)
		}
	}
	if f := parseHostForm(form("display_name", strings.Repeat("é", 200))); len(f.Problems) != 0 {
		t.Errorf("200 characters rejected: %v", f.Problems)
	}
	if f := parseHostForm(form("status_override", "gone", "criticality", "legacy")); len(f.Overrides) != 5 || len(f.Criticalities) != 6 {
		t.Errorf("unknown values are not kept as selected options: %+v %+v", f.Overrides, f.Criticalities)
	}
}

func TestHostViewReportsConfidenceTimesStabilityAndLabelsOutdated(t *testing.T) {
	d := inventory.HostDetail{Host: inventory.ExportHost{Address: "192.0.2.1", Stability: 0.5, Services: []inventory.ExportService{{
		Port: 80, Protocol: "tcp", Status: inventory.StatusActive,
		Technologies: []inventory.Technology{{Name: "nginx", Version: "1.20.1", Confidence: 90}},
		Findings:     []inventory.Finding{{SignatureID: "outdated-nginx", Kind: "outdated", Name: "Outdated nginx", Confidence: 90}},
	}}}}
	v := newHostView(d, time.Now())
	if got := v.Services[0].Technologies[0].Confidence; got != 45 {
		t.Errorf("reported confidence = %d, want 90 x 0.5 = 45", got)
	}
	if got := d.Host.Services[0].Technologies[0].Confidence; got != 90 {
		t.Errorf("host detail confidence changed to %d, want the stored 90", got)
	}
	if m := v.Services[0].Findings[0].Mark; m.Class != "outdated" || m.Label != "Outdated version" {
		t.Errorf("outdated finding mark = %+v, want class outdated with a readable label", m)
	}
}

// REQ-WEB-020
func TestHostCountWording(t *testing.T) {
	r, _ := newTestRouter(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	seen := now.Add(-5 * time.Minute)
	for _, tc := range []struct {
		total    int
		filtered bool
		want     string
	}{
		{0, false, "0 hosts in the inventory."},
		{1, false, "1 host in the inventory."},
		{2, false, "2 hosts in the inventory."},
		{1234, false, count(1234) + " hosts in the inventory."},
		{0, true, "0 matching hosts."},
		{1, true, "1 matching host."},
		{2, true, "2 matching hosts."},
		{1234, true, count(1234) + " matching hosts."},
	} {
		f := hostFilter{}
		if tc.filtered {
			f.Tag = "dmz"
		}
		p := inventory.HostPage{Total: tc.total, Page: 1, PerPage: 50}
		if tc.total > 0 {
			p.Hosts = []inventory.HostRow{{Address: "10.0.0.1", Status: inventory.StatusActive, Ports: []int{22}, LastSeen: seen}}
		}
		rec := httptest.NewRecorder()
		r.Render(rec, httptest.NewRequest(http.MethodGet, "/hosts/", nil), http.StatusOK, "inventory.html", View{Data: newHostsView(f, p, now)})
		body := rec.Body.String()
		if !strings.Contains(body, tc.want) {
			t.Errorf("total %d filtered %v: lede lacks %q", tc.total, tc.filtered, tc.want)
		}
		if tc.total > 0 && !strings.Contains(body, `<span title="`+isoTime(seen)+`">5 minutes ago</span>`) {
			t.Errorf("relative last-seen time lacks its exact time in title")
		}
	}
}

// REQ-WEB-020
func TestHostsListFindingsOmitTechnology(t *testing.T) {
	r, _ := newTestRouter(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	p := inventory.HostPage{Total: 1, Page: 1, PerPage: 50, Hosts: []inventory.HostRow{{Address: "10.0.0.1",
		Status: inventory.StatusActive, Ports: []int{443}, LastSeen: now, Technologies: []string{"WordPress"},
		FindingKinds: []string{"admin-panel", "technology"}}}}
	rec := httptest.NewRecorder()
	r.Render(rec, httptest.NewRequest(http.MethodGet, "/hosts/", nil), http.StatusOK, "inventory.html", View{Data: newHostsView(hostFilter{}, p, now)})
	body := rec.Body.String()
	for _, want := range []string{"<td>WordPress</td>", `<span class="kind admin-panel">Admin panel</span>`} {
		if !strings.Contains(body, want) {
			t.Fatalf("hosts list lacks %q:\n%s", want, body)
		}
	}
	for _, bad := range []string{`<span class="kind technology">`, `<option value="technology"`} {
		if strings.Contains(body, bad) {
			t.Errorf("hosts list shows technology as a finding kind: %q", bad)
		}
	}
}

// REQ-WEB-036
func TestHostPageKeepsTechnologiesWithSource(t *testing.T) {
	r, _ := newTestRouter(t)
	d := inventory.HostDetail{Run: "r1", Host: inventory.ExportHost{Address: "10.0.0.1", Status: inventory.StatusActive,
		Services: []inventory.ExportService{{Port: 443, Protocol: "tcp", State: "open", Status: inventory.StatusActive,
			Technologies: []inventory.Technology{{Name: "WordPress", Category: "CMS", Version: "6.4", Confidence: 90, Source: "meta-generator"}},
			Findings:     []inventory.Finding{{SignatureID: "wordpress-generator", Kind: "technology", Name: "WordPress", Confidence: 90}}}}}}
	rec := httptest.NewRecorder()
	r.Render(rec, httptest.NewRequest(http.MethodGet, "/hosts/10.0.0.1", nil), http.StatusOK, "host.html", View{Data: newHostView(d, time.Now())})
	body := rec.Body.String()
	if !strings.Contains(body, `<tr><td>WordPress</td><td>CMS</td><td>6.4</td><td class="muted">meta-generator</td>`) {
		t.Fatalf("host page lacks the technology with its source:\n%s", body)
	}
	if !strings.Contains(body, `<span class="kind technology">Technology</span>`) {
		t.Fatalf("host page lacks the technology finding:\n%s", body)
	}
}

// REQ-WEB-038
func TestHostPageListsFieldsThatChangeEveryRun(t *testing.T) {
	r, _ := newTestRouter(t)
	d := inventory.HostDetail{Run: "r4", Host: inventory.ExportHost{Address: "10.0.0.1", Status: inventory.StatusActive,
		Services: []inventory.ExportService{{Port: 80, Protocol: "tcp", State: "open", Status: inventory.StatusActive,
			HTTP: &probe.HTTP{StatusCode: 200, Title: "t3", Headers: map[string]string{}},
			Volatile: []inventory.VolatileField{
				{Field: "http.title", Values: []any{"t1", "t2", "t3"}},
				{Field: "technologies", Values: []any{[]any{"Adminer 4.8.1"}, []any{"Adminer 4.8.2"}}},
			}}}}}
	rec := httptest.NewRecorder()
	r.Render(rec, httptest.NewRequest(http.MethodGet, "/hosts/10.0.0.1", nil), http.StatusOK, "host.html", View{Data: newHostView(d, time.Now())})
	body := rec.Body.String()
	for _, want := range []string{
		"<th>Changes every run</th><th>Last values</th>",
		`<tr><td class="addr">http.title</td><td class="wrap addr">t1<br>t2<br>t3<br></td></tr>`,
		`<tr><td class="addr">technologies</td><td class="wrap addr">Adminer 4.8.1<br>Adminer 4.8.2<br></td></tr>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("host page lacks %q:\n%s", want, body)
		}
	}
	if regexp.MustCompile(`style\s*=`).MatchString(body) {
		t.Error("host page uses inline styles")
	}
}
