package web

import (
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"asi/internal/inventory"
	"asi/internal/probe"
)

func groupedService(port int, title, favicon string, techs ...string) inventory.ExportService {
	s := inventory.ExportService{Port: port, Protocol: "tcp", Status: inventory.StatusActive,
		HTTP: &probe.HTTP{StatusCode: 200, Title: title, FaviconSHA256: favicon}}
	for _, t := range techs {
		s.Technologies = append(s.Technologies, inventory.Technology{Name: t})
	}
	return s
}

func groupsInventory() *fakeInventory {
	inactive := groupedService(81, "Login", "aa", "nginx", "PHP")
	inactive.Status = inventory.StatusInactive
	exp := inventory.Export{Run: "g2", Hosts: []inventory.ExportHost{
		{Address: "10.0.0.1", Services: []inventory.ExportService{groupedService(80, "Login", "aa", "nginx", "PHP"), inactive}},
		{Address: "10.0.0.2", Services: []inventory.ExportService{groupedService(443, "Login", "aa", "PHP", "nginx")}},
		{Address: "10.0.0.3", Services: []inventory.ExportService{groupedService(8080, "Login", "aa", "nginx", "PHP"),
			groupedService(9000, `<script>x</script>`, "bb", "nginx")}},
	}}
	return &fakeInventory{exports: map[string]inventory.Export{"": exp}}
}

var groupRowRE = regexp.MustCompile(`<tr data-count="(\d+)">`)

// REQ-WEB-014
func TestGroupsPage(t *testing.T) {
	r, viewer := newChangesRouter(t, groupsInventory())
	rec := do(r, http.MethodGet, "/groups", nil, viewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /groups = %d\n%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	var counts []string
	for _, m := range groupRowRE.FindAllStringSubmatch(body, -1) {
		counts = append(counts, m[1])
	}
	if strings.Join(counts, ",") != "3,1" {
		t.Errorf("group counts = %v, want 3,1:\n%s", counts, body)
	}
	for _, want := range []string{
		`<td>PHP, nginx</td><td>Login</td><td class="addr">aa</td>`,
		`<a class="addr" href="/hosts/10.0.0.1/timeline">10.0.0.1:80</a><a class="addr" href="/hosts/10.0.0.2/timeline">10.0.0.2:443</a><a class="addr" href="/hosts/10.0.0.3/timeline">10.0.0.3:8080</a>`,
		`&lt;script&gt;x&lt;/script&gt;`,
		`as of run <strong class="addr">g2</strong>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("groups page lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<script>x") || strings.Contains(body, "style=") || strings.Contains(body, "10.0.0.1:81") {
		t.Errorf("groups page is unescaped, styled inline or lists an inactive service")
	}
}

// REQ-WEB-014
func TestGroupsEmptyAndLongGroups(t *testing.T) {
	r, viewer := newChangesRouter(t, &fakeInventory{exports: map[string]inventory.Export{"": {Hosts: []inventory.ExportHost{}}}})
	if body := do(r, http.MethodGet, "/groups", nil, viewer).Body.String(); !strings.Contains(body, "Groups appear here once a scan run has found web services.") {
		t.Errorf("no empty state:\n%s", body)
	}
	var hosts []inventory.ExportHost
	for i := 0; i < 12; i++ {
		hosts = append(hosts, inventory.ExportHost{Address: "10.1.0." + string(rune('a'+i)), Services: []inventory.ExportService{groupedService(80, "Same", "cc")}})
	}
	data := newGroupsData(inventory.Export{Hosts: hosts})
	if len(data.Groups) != 1 || data.Groups[0].Count != 12 || len(data.Groups[0].Members) != groupMembersShown || data.Groups[0].More != 2 {
		t.Errorf("long group = %+v", data.Groups)
	}
}

// REQ-WEB-007
func TestGroupsAndChartTemplatesUseNoInlineStyle(t *testing.T) {
	for _, name := range []string{"groups.html", "changes_chart.html", "dashboard.html"} {
		b, err := fs.ReadFile(files, name)
		if err != nil {
			t.Fatal(err)
		}
		if s := string(b); strings.Contains(s, "style=") || strings.Contains(s, "<style") || strings.Contains(s, "<script") {
			t.Errorf("%s has inline style or script", name)
		}
	}
	css, _ := fs.ReadFile(files, "static/app.css")
	guide, _ := fs.ReadFile(files, "static/styleguide.html")
	for _, sel := range []string{"svg.chart rect.new", "svg.chart rect.missing", "svg.chart rect.changed"} {
		if !strings.Contains(string(css), sel) {
			t.Errorf("app.css lacks %s", sel)
		}
	}
	if !strings.Contains(string(guide), `<svg class="chart"`) {
		t.Error("styleguide lacks the change chart")
	}
}
