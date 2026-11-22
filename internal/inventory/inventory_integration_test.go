//go:build integration

package inventory

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"asi/internal/probe"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func openInventory(t *testing.T) (*Inventory, *store.Store) {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatalf("master key: %v", err)
	}
	k, err := store.NewKeyring(master)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return New(s, k), s
}

func mustRun(t *testing.T, inv *Inventory, name string, n int) Run {
	t.Helper()
	r, err := inv.CreateRun(context.Background(), RunSpec{Name: name, InactiveAfter: n})
	if err != nil {
		t.Fatalf("CreateRun %s: %v", name, err)
	}
	return r
}

func mustRecord(t *testing.T, inv *Inventory, r Run, g GroupResult) {
	t.Helper()
	if err := inv.RecordGroup(context.Background(), r.ID, g); err != nil {
		t.Fatalf("RecordGroup %s/%d: %v", r.Name, g.Index, err)
	}
}

func mustExport(t *testing.T, inv *Inventory, run string) Export {
	t.Helper()
	e, err := inv.Export(context.Background(), run)
	if err != nil {
		t.Fatalf("Export(%q): %v", run, err)
	}
	return e
}

func findHost(t *testing.T, e Export, address string) ExportHost {
	t.Helper()
	for _, h := range e.Hosts {
		if h.Address == address {
			return h
		}
	}
	t.Fatalf("export of run %q has no host %s", e.Run, address)
	return ExportHost{}
}

func findService(t *testing.T, h ExportHost, port int) ExportService {
	t.Helper()
	for _, s := range h.Services {
		if s.Port == port {
			return s
		}
	}
	t.Fatalf("host %s has no service on port %d", h.Address, port)
	return ExportService{}
}

func schemaTables(t *testing.T, s *store.Store) []string {
	t.Helper()
	rows, err := s.Pool.Query(context.Background(), `SELECT table_name FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' ORDER BY table_name`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list tables: %v", err)
	}
	return out
}

func rowCounts(t *testing.T, s *store.Store) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, table := range schemaTables(t, s) {
		var n int
		if err := s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM "`+table+`"`).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		counts[table] = n
	}
	return counts
}

func exportJSON(t *testing.T, e Export) string {
	t.Helper()
	e.GeneratedAt = time.Time{}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	return string(b)
}

func webService(title string) ServiceResult {
	return ServiceResult{
		Port: 443, Protocol: "tcp", State: "open", Service: "https", Product: "nginx", Version: "1.25.3",
		HTTP: &probe.HTTP{
			Scheme: "https", URL: "https://10.0.0.1/", StatusCode: 200, Title: title,
			Headers:       map[string]string{"server": "nginx", "x-secret": "MARKER-HDR-1"},
			Cookies:       []probe.Cookie{{Name: "MARKER-CK-1", HTTPOnly: true, Secure: true, SameSite: "Lax"}},
			RedirectChain: []string{"http://10.0.0.1/"},
			TLS:           &probe.TLS{SubjectCN: "intranet", IssuerCN: "ca", SANs: []string{"intranet"}, SHA256: "ab12", SelfSigned: true},
			FaviconSHA256: "ff00", FaviconMMH3: -123,
		},
		Technologies: []Technology{
			{Name: "nginx", Category: "web-server", Version: "1.25.3", Confidence: 90, Source: "header"},
			{Name: "WordPress", Category: "cms", Version: "", Confidence: 70, Source: "signature"},
		},
		Findings: []Finding{
			{SignatureID: "admin-panel-wp", Kind: "admin_panel", Name: "WordPress login", Version: "6.4", Confidence: 80, Evidence: "MARKER-EV-1"},
		},
	}
}

func TestSensitiveColumnsEncrypted(t *testing.T) {
	ctx := context.Background()
	inv, s := openInventory(t)
	r := mustRun(t, inv, "r1", 0)
	mustRecord(t, inv, r, GroupResult{Index: 0, Addresses: []string{"10.0.0.1", "10.0.0.2"}, Hosts: []HostResult{
		{Address: "10.0.0.1", Hostnames: []string{"intranet.example"}, Services: []ServiceResult{webService("Intranet")}},
	}})
	if err := inv.UpdateHostUserFields(ctx, "10.0.0.1", HostUserFields{Notes: "MARKER-NOTE-1"}); err != nil {
		t.Fatalf("UpdateHostUserFields: %v", err)
	}

	markers := []string{"MARKER-HDR-1", "MARKER-CK-1", "MARKER-EV-1", "MARKER-NOTE-1"}
	tables := schemaTables(t, s)
	if len(tables) < 6 {
		t.Fatalf("expected the inventory tables in the test schema, got %v", tables)
	}
	for _, table := range tables {
		rows, err := s.Pool.Query(ctx, `SELECT t::text FROM "`+table+`" t`)
		if err != nil {
			t.Fatalf("select %s: %v", table, err)
		}
		for rows.Next() {
			var text string
			if err := rows.Scan(&text); err != nil {
				t.Fatalf("scan %s: %v", table, err)
			}
			for _, m := range markers {
				if strings.Contains(text, m) {
					t.Errorf("table %s holds %s in plain text: %s", table, m, text)
				}
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("select %s: %v", table, err)
		}
	}

	h := findHost(t, mustExport(t, inv, ""), "10.0.0.1")
	if h.Notes != "MARKER-NOTE-1" {
		t.Errorf("notes = %q", h.Notes)
	}
	svc := findService(t, h, 443)
	if svc.HTTP == nil {
		t.Fatal("service has no http")
	}
	if got := svc.HTTP.Headers["x-secret"]; got != "MARKER-HDR-1" {
		t.Errorf("header x-secret = %q", got)
	}
	if len(svc.HTTP.Cookies) != 1 || svc.HTTP.Cookies[0].Name != "MARKER-CK-1" {
		t.Errorf("cookies = %+v", svc.HTTP.Cookies)
	}
	if len(svc.Findings) != 1 || svc.Findings[0].Evidence != "MARKER-EV-1" {
		t.Errorf("findings = %+v", svc.Findings)
	}
}

func TestRoundTripTechnologiesFindings(t *testing.T) {
	inv, _ := openInventory(t)
	r := mustRun(t, inv, "r1", 0)
	in := webService("Intranet")
	mustRecord(t, inv, r, GroupResult{Index: 0, Addresses: []string{"10.0.0.1"}, Hosts: []HostResult{
		{Address: "10.0.0.1", Services: []ServiceResult{in}},
	}})
	svc := findService(t, findHost(t, mustExport(t, inv, "r1"), "10.0.0.1"), 443)
	if !reflect.DeepEqual(svc.Technologies, in.Technologies) {
		t.Errorf("technologies = %+v, want %+v", svc.Technologies, in.Technologies)
	}
	if !reflect.DeepEqual(svc.Findings, in.Findings) {
		t.Errorf("findings = %+v, want %+v", svc.Findings, in.Findings)
	}
	if !reflect.DeepEqual(svc.HTTP, in.HTTP) {
		t.Errorf("http = %+v, want %+v", svc.HTTP, in.HTTP)
	}
	if svc.Service != "https" || svc.Product != "nginx" || svc.Version != "1.25.3" || svc.State != "open" {
		t.Errorf("service fields = %+v", svc)
	}
}

func TestRecordGroupIdempotent(t *testing.T) {
	inv, s := openInventory(t)
	r := mustRun(t, inv, "r1", 0)
	g0 := GroupResult{Index: 0, Addresses: []string{"10.0.0.1", "10.0.0.2"}, Hosts: []HostResult{
		{Address: "10.0.0.1", Hostnames: []string{"a.example"}, Services: []ServiceResult{webService("A"), {Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}},
	}}
	mustRecord(t, inv, r, g0)
	first := rowCounts(t, s)
	firstExport := exportJSON(t, mustExport(t, inv, "r1"))

	mustRecord(t, inv, r, g0)
	second := rowCounts(t, s)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("row counts changed on re-recording the same group:\nfirst  %v\nsecond %v", first, second)
	}
	if got := exportJSON(t, mustExport(t, inv, "r1")); got != firstExport {
		t.Errorf("export changed on re-recording the same group:\nfirst  %s\nsecond %s", firstExport, got)
	}
	for _, table := range []string{"host_observations", "service_observations", "technologies", "findings"} {
		if first[table] == 0 {
			t.Errorf("table %s is empty after recording", table)
		}
	}

	mustRecord(t, inv, r, GroupResult{Index: 1, Addresses: []string{"10.0.1.1"}, Hosts: []HostResult{
		{Address: "10.0.1.1", Services: []ServiceResult{webService("B")}},
	}})
	third := rowCounts(t, s)
	want := map[string]int{"host_observations": 1, "service_observations": 1, "technologies": 2, "findings": 1, "run_groups": 1, "run_group_addresses": 1}
	for table, add := range want {
		if third[table] != second[table]+add {
			t.Errorf("table %s: %d rows after group 1, want %d", table, third[table], second[table]+add)
		}
	}
	e := mustExport(t, inv, "r1")
	if len(e.Hosts) != 2 {
		t.Errorf("export has %d hosts, want 2", len(e.Hosts))
	}
}

func TestRecordGroupUnknownRun(t *testing.T) {
	inv, s := openInventory(t)
	before := rowCounts(t, s)
	err := inv.RecordGroup(context.Background(), 987654, GroupResult{Index: 0, Addresses: []string{"10.0.0.1"}, Hosts: []HostResult{
		{Address: "10.0.0.1", Services: []ServiceResult{webService("A")}},
	}})
	if err == nil {
		t.Fatal("RecordGroup with an unknown run returned nil")
	}
	if !errors.Is(err, ErrUnknownRun) {
		t.Errorf("error = %v, want ErrUnknownRun", err)
	}
	if after := rowCounts(t, s); !reflect.DeepEqual(before, after) {
		t.Errorf("RecordGroup with an unknown run wrote rows:\nbefore %v\nafter  %v", before, after)
	}
}

func checkStatus(t *testing.T, what string, status Status, missed int, stability float64, wantStatus Status, wantMissed int, wantStability float64) {
	t.Helper()
	if status != wantStatus || missed != wantMissed || math.Abs(stability-wantStability) > 1e-9 {
		t.Errorf("%s: status %s missed %d stability %v, want %s %d %v", what, status, missed, stability, wantStatus, wantMissed, wantStability)
	}
}

func TestStatusCoveringRuns(t *testing.T) {
	const h, h2, other = "10.0.0.1", "10.0.0.2", "10.0.1.1"
	group0 := []string{h, h2}
	svc := func(port int) ServiceResult { return ServiceResult{Port: port, Protocol: "tcp", State: "open"} }

	history := func(t *testing.T, n int) (*Inventory, []Run) {
		inv, _ := openInventory(t)
		var runs []Run
		for _, name := range []string{"r1", "r2", "r3", "r4"} {
			runs = append(runs, mustRun(t, inv, name, n))
		}
		mustRecord(t, inv, runs[0], GroupResult{Index: 0, Addresses: group0, Hosts: []HostResult{
			{Address: h, Services: []ServiceResult{svc(80)}},
			{Address: h2, Services: []ServiceResult{svc(80), svc(443)}},
		}})
		mustRecord(t, inv, runs[1], GroupResult{Index: 0, Addresses: group0, Hosts: []HostResult{
			{Address: h2, Services: []ServiceResult{svc(80)}},
		}})
		mustRecord(t, inv, runs[2], GroupResult{Index: 1, Addresses: []string{other}, Hosts: []HostResult{
			{Address: other},
		}})
		mustRecord(t, inv, runs[3], GroupResult{Index: 0, Addresses: group0, Hosts: []HostResult{
			{Address: h2, Services: []ServiceResult{svc(80)}},
		}})
		return inv, runs
	}

	t.Run("inactive after 2", func(t *testing.T) {
		inv, _ := history(t, 2)
		e1 := mustExport(t, inv, "r1")
		x := findHost(t, e1, h)
		checkStatus(t, "r1 host", x.Status, x.MissedRuns, x.Stability, StatusActive, 0, 1)

		e2 := mustExport(t, inv, "r2")
		x = findHost(t, e2, h)
		checkStatus(t, "r2 host", x.Status, x.MissedRuns, x.Stability, StatusUnstable, 1, 0.5)
		s := findService(t, x, 80)
		checkStatus(t, "r2 host service 80", s.Status, s.MissedRuns, s.Stability, StatusUnstable, 1, 0.5)
		y := findHost(t, e2, h2)
		checkStatus(t, "r2 h2", y.Status, y.MissedRuns, y.Stability, StatusActive, 0, 1)
		s = findService(t, y, 443)
		checkStatus(t, "r2 h2 service 443", s.Status, s.MissedRuns, s.Stability, StatusUnstable, 1, 0.5)
		s = findService(t, y, 80)
		checkStatus(t, "r2 h2 service 80", s.Status, s.MissedRuns, s.Stability, StatusActive, 0, 1)

		e3 := mustExport(t, inv, "r3")
		x = findHost(t, e3, h)
		checkStatus(t, "r3 host (group not completed)", x.Status, x.MissedRuns, x.Stability, StatusUnstable, 1, 0.5)
		s = findService(t, x, 80)
		checkStatus(t, "r3 host service 80", s.Status, s.MissedRuns, s.Stability, StatusUnstable, 1, 0.5)

		e4 := mustExport(t, inv, "r4")
		x = findHost(t, e4, h)
		checkStatus(t, "r4 host", x.Status, x.MissedRuns, x.Stability, StatusInactive, 2, 1.0/3)
		s = findService(t, x, 80)
		checkStatus(t, "r4 host service 80", s.Status, s.MissedRuns, s.Stability, StatusInactive, 2, 1.0/3)
		y = findHost(t, e4, h2)
		checkStatus(t, "r4 h2", y.Status, y.MissedRuns, y.Stability, StatusActive, 0, 1)
		s = findService(t, y, 443)
		checkStatus(t, "r4 h2 service 443", s.Status, s.MissedRuns, s.Stability, StatusInactive, 2, 1.0/3)
	})

	t.Run("inactive after 5", func(t *testing.T) {
		inv, _ := history(t, 5)
		x := findHost(t, mustExport(t, inv, "r4"), h)
		checkStatus(t, "r4 host", x.Status, x.MissedRuns, x.Stability, StatusUnstable, 2, 1.0/3)
		s := findService(t, x, 80)
		checkStatus(t, "r4 host service 80", s.Status, s.MissedRuns, s.Stability, StatusUnstable, 2, 1.0/3)
	})
}

func TestUserFieldsSurviveRecordGroup(t *testing.T) {
	ctx := context.Background()
	inv, _ := openInventory(t)
	const h = "10.0.0.1"
	addrs := []string{h}
	r1 := mustRun(t, inv, "r1", 0)
	mustRecord(t, inv, r1, GroupResult{Index: 0, Addresses: addrs, Hosts: []HostResult{
		{Address: h, Hostnames: []string{"one.example"}, Services: []ServiceResult{{Port: 22, Protocol: "tcp", State: "open"}}},
	}})
	edited := HostUserFields{Tags: []string{"crown-jewel"}, Notes: "n1", DisplayName: "d", Owner: "o", Criticality: "high", StatusOverride: "inactive"}
	if err := inv.UpdateHostUserFields(ctx, h, edited); err != nil {
		t.Fatalf("UpdateHostUserFields: %v", err)
	}

	r2 := mustRun(t, inv, "r2", 0)
	mustRecord(t, inv, r2, GroupResult{Index: 0, Addresses: addrs, Hosts: []HostResult{
		{Address: h, Hostnames: []string{"two.example"}, Services: []ServiceResult{webService("Two")}},
	}})
	r3 := mustRun(t, inv, "r3", 0)
	mustRecord(t, inv, r3, GroupResult{Index: 0, Addresses: addrs, Hosts: []HostResult{
		{Address: h, Hostnames: []string{"three.example", "alias.example"}, Services: []ServiceResult{{Port: 8080, Protocol: "tcp", State: "open"}}},
	}})
	r4 := mustRun(t, inv, "r4", 0)
	mustRecord(t, inv, r4, GroupResult{Index: 0, Addresses: addrs})

	got, err := inv.GetHostUserFields(ctx, h)
	if err != nil {
		t.Fatalf("GetHostUserFields: %v", err)
	}
	if !reflect.DeepEqual(got, edited) {
		t.Errorf("user fields = %+v, want %+v", got, edited)
	}
	x := findHost(t, mustExport(t, inv, ""), h)
	if !reflect.DeepEqual(x.Tags, []string{"crown-jewel"}) || x.Notes != "n1" {
		t.Errorf("export tags %v notes %q", x.Tags, x.Notes)
	}
	if x.DisplayName != "d" || x.Owner != "o" || x.Criticality != "high" || x.StatusOverride != "inactive" {
		t.Errorf("export user fields = %+v", x)
	}
	if !reflect.DeepEqual(x.Hostnames, []string{"alias.example", "three.example"}) {
		t.Errorf("hostnames = %v, want the scanned ones of r3", x.Hostnames)
	}
}

func TestUpdateUnknownHost(t *testing.T) {
	inv, s := openInventory(t)
	err := inv.UpdateHostUserFields(context.Background(), "10.9.9.9", HostUserFields{Tags: []string{"x"}, Notes: "n"})
	if !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("UpdateHostUserFields on unknown host = %v, want ErrUnknownHost", err)
	}
	if n := rowCounts(t, s)["hosts"]; n != 0 {
		t.Errorf("hosts has %d rows, want 0", n)
	}
}

func TestEditHostUserFieldsWritesAudit(t *testing.T) {
	ctx := context.Background()
	inv, s := openInventory(t)
	r := mustRun(t, inv, "e1", 3)
	mustRecord(t, inv, r, GroupResult{Index: 0, Hosts: []HostResult{{Address: "10.3.0.1"}}})
	f := HostUserFields{Tags: []string{"dmz"}, Notes: "n", DisplayName: "D", Owner: "O", Criticality: "high", StatusOverride: "active"}
	if err := inv.EditHostUserFields(ctx, Editor{Username: "olga", Addr: "192.0.2.7"}, "10.3.0.1", f); err != nil {
		t.Fatalf("EditHostUserFields: %v", err)
	}
	if got, err := inv.GetHostUserFields(ctx, "10.3.0.1"); err != nil || !reflect.DeepEqual(got, f) {
		t.Errorf("GetHostUserFields = %+v, %v", got, err)
	}
	var actor, target, addr string
	if err := s.Pool.QueryRow(ctx, `SELECT actor, target, address FROM audit_log WHERE action = 'host.edit'`).Scan(&actor, &target, &addr); err != nil ||
		actor != "olga" || target != "10.3.0.1" || addr != "192.0.2.7" {
		t.Errorf("audit row = %q %q %q, %v", actor, target, addr, err)
	}
	for name, call := range map[string]error{
		"unknown host":    inv.EditHostUserFields(ctx, Editor{Username: "olga"}, "10.3.0.9", f),
		"bad override":    inv.EditHostUserFields(ctx, Editor{Username: "olga"}, "10.3.0.1", HostUserFields{StatusOverride: "gone"}),
		"invalid address": inv.EditHostUserFields(ctx, Editor{Username: "olga"}, "nope", f),
	} {
		if call == nil {
			t.Errorf("%s: no error", name)
		}
	}
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'host.edit'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("audit rows = %d, %v; failed edits must not be audited", n, err)
	}
}

// REQ-INVENTORY-005 AC1: owner, display name and the targets and excludes of a run are stored encrypted and read back in plain text.
func TestOwnerDisplayNameAndRunScopeEncrypted(t *testing.T) {
	ctx := context.Background()
	inv, s := openInventory(t)
	r, err := inv.CreateRun(ctx, RunSpec{Name: "r1", Settings: RunSettings{Targets: []string{"MARKER-TARGET-1"}, Excludes: []string{"MARKER-EXCL-1"}, Ports: []int{80}}})
	if err != nil {
		t.Fatal(err)
	}
	mustRecord(t, inv, r, GroupResult{Index: 0, Addresses: []string{"10.0.0.1"}, Hosts: []HostResult{{Address: "10.0.0.1"}}})
	if err := inv.UpdateHostUserFields(ctx, "10.0.0.1", HostUserFields{DisplayName: "MARKER-NAME-1", Owner: "MARKER-OWNER-1"}); err != nil {
		t.Fatal(err)
	}
	for _, table := range schemaTables(t, s) {
		var text string
		if err := s.Pool.QueryRow(ctx, `SELECT COALESCE(string_agg(t::text, ' '), '') FROM "`+table+`" t`).Scan(&text); err != nil {
			t.Fatalf("select %s: %v", table, err)
		}
		for _, m := range []string{"MARKER-TARGET-1", "MARKER-EXCL-1", "MARKER-NAME-1", "MARKER-OWNER-1"} {
			if strings.Contains(text, m) {
				t.Errorf("table %s holds %s in plain text", table, m)
			}
		}
	}
	h := findHost(t, mustExport(t, inv, ""), "10.0.0.1")
	if h.DisplayName != "MARKER-NAME-1" || h.Owner != "MARKER-OWNER-1" {
		t.Errorf("export display name %q owner %q", h.DisplayName, h.Owner)
	}
	page, err := inv.ListHosts(ctx, HostQuery{Text: "marker-name"})
	if err != nil || page.Total != 1 || page.Hosts[0].DisplayName != "MARKER-NAME-1" {
		t.Errorf("search by display name = %+v, %v", page, err)
	}
	got, err := inv.RunByName(ctx, "r1")
	if err != nil || !slices.Equal(got.Settings.Targets, []string{"MARKER-TARGET-1"}) || !slices.Equal(got.Settings.Excludes, []string{"MARKER-EXCL-1"}) {
		t.Errorf("run settings = %+v, %v", got.Settings, err)
	}
}
