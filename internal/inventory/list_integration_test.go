//go:build integration

package inventory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

	"asi/internal/probe"
	"asi/internal/store"
)

type summaryRecord struct {
	Address      string
	LastRunID    int64
	Status       Status
	MissedRuns   int
	Stability    float64
	Interest     int
	Ports        []int32
	Services     []string
	Technologies []string
	FindingKinds []string
	Titles       []string
	Hostnames    []string
	FirstSeen    time.Time
	LastSeen     time.Time
}

func readSummary(t *testing.T, s *store.Store) map[string]summaryRecord {
	t.Helper()
	rows, err := s.Pool.Query(context.Background(), `SELECT host(address), last_run_id, status, missed_runs, stability,
		interest_score, ports, services, technologies, finding_kinds, titles, hostnames, first_seen, last_seen
		FROM host_summary ORDER BY address`)
	if err != nil {
		t.Fatalf("read host_summary: %v", err)
	}
	defer rows.Close()
	out := map[string]summaryRecord{}
	for rows.Next() {
		var r summaryRecord
		if err := rows.Scan(&r.Address, &r.LastRunID, &r.Status, &r.MissedRuns, &r.Stability, &r.Interest, &r.Ports,
			&r.Services, &r.Technologies, &r.FindingKinds, &r.Titles, &r.Hostnames, &r.FirstSeen, &r.LastSeen); err != nil {
			t.Fatalf("scan host_summary: %v", err)
		}
		out[r.Address] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read host_summary: %v", err)
	}
	return out
}

func assertSummaryMatchesExport(t *testing.T, step string, inv *Inventory, s *store.Store) map[string]summaryRecord {
	t.Helper()
	e := mustExport(t, inv, "")
	sum := readSummary(t, s)
	if len(sum) != len(e.Hosts) {
		t.Errorf("%s: host_summary has %d rows, export has %d hosts", step, len(sum), len(e.Hosts))
	}
	for _, h := range e.Hosts {
		r, ok := sum[h.Address]
		if !ok {
			t.Errorf("%s: host_summary has no row for %s", step, h.Address)
			continue
		}
		if r.Status != h.Status || r.MissedRuns != h.MissedRuns || math.Abs(r.Stability-h.Stability) > 1e-9 {
			t.Errorf("%s: %s summary status/missed/stability = %s/%d/%v, export %s/%d/%v",
				step, h.Address, r.Status, r.MissedRuns, r.Stability, h.Status, h.MissedRuns, h.Stability)
		}
		if r.Interest != h.InterestScore {
			t.Errorf("%s: %s summary interest %d, export %d", step, h.Address, r.Interest, h.InterestScore)
		}
		if !r.FirstSeen.Equal(h.FirstSeen) || !r.LastSeen.Equal(h.LastSeen) {
			t.Errorf("%s: %s summary first/last seen %s/%s, export %s/%s",
				step, h.Address, r.FirstSeen, r.LastSeen, h.FirstSeen, h.LastSeen)
		}
		if !reflect.DeepEqual(r.Hostnames, h.Hostnames) {
			t.Errorf("%s: %s summary hostnames %v, export %v", step, h.Address, r.Hostnames, h.Hostnames)
		}
	}
	return sum
}

func TestHostSummaryMatchesExport(t *testing.T) {
	ctx := context.Background()
	inv, s := openInventory(t)
	const A, B, C, D, E = "10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4", "10.1.0.5"
	hostA := HostResult{Address: A, Hostnames: []string{"admin.example"}, Services: []ServiceResult{{
		Port: 80, Protocol: "tcp", State: "open", Service: "http",
		HTTP:     &probe.HTTP{Scheme: "http", URL: "http://10.1.0.1/", StatusCode: 200, Title: "Admin"},
		Findings: []Finding{{SignatureID: "admin-panel-login", Kind: "admin-panel", Confidence: 80}},
	}}}
	hostB := HostResult{Address: B, Services: []ServiceResult{{Port: 443, Protocol: "tcp", State: "open", Service: "http",
		HTTP: &probe.HTTP{Scheme: "https", TLS: &probe.TLS{SelfSigned: true, NotAfter: time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339)}}}}}
	hostC := HostResult{Address: C, Services: []ServiceResult{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}}
	hostD := HostResult{Address: D}
	hostD2 := HostResult{Address: D, Services: []ServiceResult{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}}
	hostE := HostResult{Address: E, Services: []ServiceResult{{Port: 8080, Protocol: "tcp", State: "open", Service: "http",
		Technologies: []Technology{{Name: "nginx", Confidence: 90, Source: "builtin"}}}}}

	r1 := mustRun(t, inv, "s1", 2)
	mustRecord(t, inv, r1, GroupResult{Index: 0, Addresses: []string{A, B, E}, Hosts: []HostResult{hostA, hostB}})
	mustRecord(t, inv, r1, GroupResult{Index: 1, Addresses: []string{C, D}, Hosts: []HostResult{hostC, hostD}})
	assertSummaryMatchesExport(t, "r1", inv, s)

	r2 := mustRun(t, inv, "s2", 2)
	mustRecord(t, inv, r2, GroupResult{Index: 0, Addresses: []string{A, B, E}, Hosts: []HostResult{hostA}})
	mustRecord(t, inv, r2, GroupResult{Index: 1, Addresses: []string{C, D}, Hosts: []HostResult{hostC, hostD2}})
	assertSummaryMatchesExport(t, "r2", inv, s)

	r3 := mustRun(t, inv, "s3", 2)
	mustRecord(t, inv, r3, GroupResult{Index: 0, Addresses: []string{A, B, E}, Hosts: []HostResult{hostA}})
	sum := assertSummaryMatchesExport(t, "r3 with group 1 not recorded", inv, s)
	if got := sum[B]; got.Status != StatusInactive || got.MissedRuns != 2 {
		t.Errorf("r3: B = %s/%d, want inactive/2", got.Status, got.MissedRuns)
	}
	if got := sum[C]; got.Status != StatusActive || got.LastRunID != r2.ID {
		t.Errorf("r3: C (group not recorded) = %s last run %d, want active as of run %d", got.Status, got.LastRunID, r2.ID)
	}

	r4 := mustRun(t, inv, "s4", 2)
	mustRecord(t, inv, r4, GroupResult{Index: 0, Addresses: []string{A, B, E}, Hosts: []HostResult{hostA}})
	mustRecord(t, inv, r4, GroupResult{Index: 1, Addresses: []string{C, D}, Hosts: []HostResult{hostC}})
	if err := inv.RecordLateHosts(ctx, r4.ID, []HostResult{hostE}); err != nil {
		t.Fatalf("RecordLateHosts: %v", err)
	}
	sum = assertSummaryMatchesExport(t, "r4", inv, s)

	want := map[string]Status{A: StatusActive, B: StatusInactive, C: StatusActive, D: StatusUnstable, E: StatusActive}
	for addr, st := range want {
		if sum[addr].Status != st {
			t.Errorf("r4: %s status %s, want %s", addr, sum[addr].Status, st)
		}
	}
	if a := sum[A]; !reflect.DeepEqual(a.Ports, []int32{80}) || !reflect.DeepEqual(a.FindingKinds, []string{"admin-panel"}) ||
		!reflect.DeepEqual(a.Titles, []string{"Admin"}) || !reflect.DeepEqual(a.Services, []string{"http"}) ||
		!reflect.DeepEqual(a.Hostnames, []string{"admin.example"}) || a.Interest != 30+10 {
		t.Errorf("r4: A summary = %+v", a)
	}
	if b := sum[B]; !reflect.DeepEqual(b.Ports, []int32{443}) {
		t.Errorf("r4: inactive B keeps its last known ports, got %v", b.Ports)
	}
	if e := sum[E]; !reflect.DeepEqual(e.Technologies, []string{"nginx"}) || e.LastRunID != r4.ID {
		t.Errorf("r4: late host E summary = %+v", e)
	}
	if exp := findHost(t, mustExport(t, inv, ""), A); exp.InterestScore != 40 {
		t.Errorf("export interest_score of A = %d, want 40", exp.InterestScore)
	}

	mustRecord(t, inv, r4, GroupResult{Index: 1, Addresses: []string{C, D}, Hosts: []HostResult{hostC}})
	if again := readSummary(t, s); !reflect.DeepEqual(again, sum) {
		t.Errorf("replaying group 1 of r4 changed host_summary:\nbefore %+v\nafter  %+v", sum, again)
	}

	if err := inv.UpdateHostUserFields(ctx, C, HostUserFields{Tags: []string{"edited"}, DisplayName: "Cee"}); err != nil {
		t.Fatalf("UpdateHostUserFields: %v", err)
	}
	if again := readSummary(t, s); !reflect.DeepEqual(again, sum) {
		t.Errorf("a user edit changed host_summary")
	}

	if _, err := s.Pool.Exec(ctx, `DELETE FROM host_summary`); err != nil {
		t.Fatalf("clear host_summary: %v", err)
	}
	if err := inv.RefreshSummary(ctx); err != nil {
		t.Fatalf("RefreshSummary: %v", err)
	}
	if rebuilt := readSummary(t, s); !reflect.DeepEqual(rebuilt, sum) {
		t.Errorf("RefreshSummary differs from the pipeline-maintained summary:\nwant %+v\ngot  %+v", sum, rebuilt)
	}
}

func listHostsFixture(t *testing.T) *Inventory {
	t.Helper()
	ctx := context.Background()
	inv, _ := openInventory(t)
	far := time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	http := func(port int, title string, techs ...string) ServiceResult {
		s := ServiceResult{Port: port, Protocol: "tcp", State: "open", Service: "http",
			HTTP: &probe.HTTP{Scheme: "http", StatusCode: 200, Title: title}}
		for _, n := range techs {
			s.Technologies = append(s.Technologies, Technology{Name: n, Confidence: 90, Source: "builtin"})
		}
		return s
	}
	svc := func(port int, name string) ServiceResult {
		return ServiceResult{Port: port, Protocol: "tcp", State: "open", Service: name}
	}
	finding := func(s ServiceResult, kind string) ServiceResult {
		s.Findings = append(s.Findings, Finding{SignatureID: kind + "-sig", Kind: kind, Confidence: 80})
		return s
	}
	tlsSvc := http(443, "Staging box", "Apache")
	tlsSvc.HTTP.Scheme = "https"
	tlsSvc.HTTP.TLS = &probe.TLS{SelfSigned: true, NotAfter: far}

	type spec struct {
		host HostResult
		seen [3]bool
		user HostUserFields
	}
	all := [3]bool{true, true, true}
	specs := []spec{
		{HostResult{Address: "10.0.0.1", Services: []ServiceResult{finding(http(80, "Intranet portal", "nginx"), "admin-panel")}}, all,
			HostUserFields{Tags: []string{"dmz"}, DisplayName: "Portal"}},
		{HostResult{Address: "10.0.0.2", Services: []ServiceResult{svc(22, "ssh")}}, all, HostUserFields{}},
		{HostResult{Address: "10.0.0.3", Services: []ServiceResult{finding(tlsSvc, "staging")}}, [3]bool{true, true, false}, HostUserFields{}},
		{HostResult{Address: "10.0.0.4", Services: []ServiceResult{finding(svc(23, "telnet"), "iot")}}, [3]bool{true, false, false}, HostUserFields{}},
		{HostResult{Address: "10.0.0.5", Services: []ServiceResult{http(80, "Blog 100%_off", "WordPress", "PHP")}}, all,
			HostUserFields{Tags: []string{"dmz", "crown-jewel"}}},
		{HostResult{Address: "10.0.0.6", Hostnames: []string{"db.example"}, Services: []ServiceResult{svc(22, "ssh"), http(80, "DB admin", "nginx")}}, all,
			HostUserFields{DisplayName: "Database"}},
		{HostResult{Address: "10.0.0.7", Services: []ServiceResult{finding(http(8080, "", "nginx"), "interesting-header")}}, [3]bool{true, true, false}, HostUserFields{}},
		{HostResult{Address: "10.0.0.8"}, all, HostUserFields{}},
		{HostResult{Address: "10.0.0.9", Services: []ServiceResult{http(80, "New thing")}}, [3]bool{false, false, true}, HostUserFields{}},
		{HostResult{Address: "10.0.0.10", Services: []ServiceResult{svc(22, "ssh")}}, all, HostUserFields{}},
		{HostResult{Address: "10.0.0.11", Services: []ServiceResult{http(80, "Old", "nginx")}}, [3]bool{true, false, false}, HostUserFields{}},
		{HostResult{Address: "10.0.0.12", Services: []ServiceResult{svc(3306, "mysql")}}, all,
			HostUserFields{Tags: []string{"crown-jewel"}, DisplayName: "Billing"}},
	}
	var addresses []string
	for _, sp := range specs {
		addresses = append(addresses, sp.host.Address)
	}
	for r := 0; r < 3; r++ {
		run := mustRun(t, inv, fmt.Sprintf("l%d", r+1), 2)
		var hosts []HostResult
		for _, sp := range specs {
			if sp.seen[r] {
				hosts = append(hosts, sp.host)
			}
		}
		mustRecord(t, inv, run, GroupResult{Index: 0, Addresses: addresses, Hosts: hosts})
	}
	for _, sp := range specs {
		if sp.user.Tags != nil || sp.user.DisplayName != "" {
			if err := inv.UpdateHostUserFields(ctx, sp.host.Address, sp.user); err != nil {
				t.Fatalf("UpdateHostUserFields %s: %v", sp.host.Address, err)
			}
		}
	}
	return inv
}

func TestListHosts(t *testing.T) {
	ctx := context.Background()
	inv := listHostsFixture(t)
	a := func(ns ...int) []string {
		out := []string{}
		for _, n := range ns {
			out = append(out, fmt.Sprintf("10.0.0.%d", n))
		}
		return out
	}
	byAddress := a(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
	cases := []struct {
		name  string
		q     HostQuery
		want  []string
		total int
	}{
		{"default sort is numeric address", HostQuery{}, byAddress, 12},
		{"address asc", HostQuery{Sort: "address"}, byAddress, 12},
		{"address desc", HostQuery{Sort: "address", Desc: true}, a(12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1), 12},
		{"status asc", HostQuery{Sort: "status"}, a(1, 2, 5, 6, 8, 9, 10, 12, 3, 7, 4, 11), 12},
		{"status desc", HostQuery{Sort: "status", Desc: true}, a(4, 11, 3, 7, 1, 2, 5, 6, 8, 9, 10, 12), 12},
		{"interest desc", HostQuery{Sort: "interest", Desc: true}, a(1, 3, 7, 9, 2, 4, 5, 6, 8, 10, 11, 12), 12},
		{"interest asc", HostQuery{Sort: "interest"}, a(2, 4, 5, 6, 8, 10, 11, 12, 7, 9, 1, 3), 12},
		{"last seen asc", HostQuery{Sort: "last_seen"}, a(4, 11, 3, 7, 1, 2, 5, 6, 8, 9, 10, 12), 12},
		{"last seen desc", HostQuery{Sort: "last_seen", Desc: true}, a(1, 2, 5, 6, 8, 9, 10, 12, 3, 7, 4, 11), 12},
		{"display name asc", HostQuery{Sort: "display_name"}, a(2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 6, 1), 12},
		{"display name desc", HostQuery{Sort: "display_name", Desc: true}, a(1, 6, 12, 2, 3, 4, 5, 7, 8, 9, 10, 11), 12},
		{"status active", HostQuery{Status: "active"}, a(1, 2, 5, 6, 8, 9, 10, 12), 8},
		{"status unstable", HostQuery{Status: "unstable"}, a(3, 7), 2},
		{"status inactive", HostQuery{Status: "inactive"}, a(4, 11), 2},
		{"port 80", HostQuery{Port: 80}, a(1, 5, 6, 9, 11), 5},
		{"port 22", HostQuery{Port: 22}, a(2, 6, 10), 3},
		{"port of an inactive host", HostQuery{Port: 23}, a(4), 1},
		{"port nobody has", HostQuery{Port: 9999}, a(), 0},
		{"service ssh", HostQuery{Service: "ssh"}, a(2, 6, 10), 3},
		{"service http", HostQuery{Service: "http"}, a(1, 3, 5, 6, 7, 9, 11), 7},
		{"technology nginx", HostQuery{Technology: "nginx"}, a(1, 6, 7, 11), 4},
		{"technology WordPress", HostQuery{Technology: "WordPress"}, a(5), 1},
		{"technology unknown", HostQuery{Technology: "nope"}, a(), 0},
		{"finding admin-panel", HostQuery{FindingKind: "admin-panel"}, a(1), 1},
		{"finding staging", HostQuery{FindingKind: "staging"}, a(3), 1},
		{"finding iot", HostQuery{FindingKind: "iot"}, a(4), 1},
		{"finding interesting-header", HostQuery{FindingKind: "interesting-header"}, a(7), 1},
		{"tag dmz", HostQuery{Tag: "dmz"}, a(1, 5), 2},
		{"tag crown-jewel", HostQuery{Tag: "crown-jewel"}, a(5, 12), 2},
		{"text in title and display name, case-insensitive", HostQuery{Text: "PORTAL"}, a(1), 1},
		{"text in hostname", HostQuery{Text: "db.example"}, a(6), 1},
		{"text in address", HostQuery{Text: "10.0.0.1"}, a(1, 10, 11, 12), 4},
		{"text with like wildcards is literal", HostQuery{Text: "%_"}, a(5), 1},
		{"text with quote is a value", HostQuery{Text: "' OR '1'='1"}, a(), 0},
		{"combined", HostQuery{Status: "active", Service: "http", Tag: "dmz"}, a(1, 5), 2},
		{"combined narrow", HostQuery{Status: "active", Service: "http", Tag: "dmz", Technology: "nginx", Text: "intranet"}, a(1), 1},
		{"combined with sort", HostQuery{Port: 80, Sort: "interest", Desc: true}, a(1, 9, 5, 6, 11), 5},
		{"first page", HostQuery{PerPage: 5}, a(1, 2, 3, 4, 5), 12},
		{"middle page", HostQuery{PerPage: 5, Page: 2}, a(6, 7, 8, 9, 10), 12},
		{"last partial page", HostQuery{PerPage: 5, Page: 3}, a(11, 12), 12},
		{"page past the end", HostQuery{PerPage: 5, Page: 4}, a(), 12},
		{"far page past the end", HostQuery{PerPage: 5, Page: 1 << 40}, a(), 12},
		{"page zero is the first", HostQuery{PerPage: 5, Page: 0}, a(1, 2, 3, 4, 5), 12},
		{"negative page is the first", HostQuery{PerPage: 5, Page: -3}, a(1, 2, 3, 4, 5), 12},
		{"paged sort keeps tie-breaker", HostQuery{Sort: "interest", Desc: true, PerPage: 4, Page: 2}, a(2, 4, 5, 6), 12},
		{"paged filter", HostQuery{Service: "http", PerPage: 3, Page: 3}, a(11), 7},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := inv.ListHosts(ctx, c.q)
			if err != nil {
				t.Fatalf("ListHosts(%+v): %v", c.q, err)
			}
			got := []string{}
			for _, h := range p.Hosts {
				got = append(got, h.Address)
			}
			if !reflect.DeepEqual(got, c.want) || p.Total != c.total {
				t.Errorf("ListHosts(%+v) = %v total %d; want %v total %d", c.q, got, p.Total, c.want, c.total)
			}
		})
	}

	t.Run("page metadata", func(t *testing.T) {
		for _, c := range []struct {
			q             HostQuery
			page, perPage int
		}{
			{HostQuery{}, 1, DefaultPerPage},
			{HostQuery{PerPage: -1}, 1, DefaultPerPage},
			{HostQuery{PerPage: 7, Page: 2}, 2, 7},
			{HostQuery{PerPage: 100000}, 1, MaxPerPage},
			{HostQuery{Page: -5}, 1, DefaultPerPage},
		} {
			p, err := inv.ListHosts(ctx, c.q)
			if err != nil {
				t.Fatalf("ListHosts(%+v): %v", c.q, err)
			}
			if p.Page != c.page || p.PerPage != c.perPage {
				t.Errorf("ListHosts(%+v) page/per page = %d/%d, want %d/%d", c.q, p.Page, p.PerPage, c.page, c.perPage)
			}
		}
	})

	t.Run("row contents", func(t *testing.T) {
		p, err := inv.ListHosts(ctx, HostQuery{Text: "intranet"})
		if err != nil || len(p.Hosts) != 1 {
			t.Fatalf("ListHosts = %+v, %v", p, err)
		}
		h := p.Hosts[0]
		if h.Address != "10.0.0.1" || h.DisplayName != "Portal" || !reflect.DeepEqual(h.Tags, []string{"dmz"}) ||
			h.Status != StatusActive || h.MissedRuns != 0 || h.Stability != 1 || h.InterestScore != 40 ||
			!reflect.DeepEqual(h.Ports, []int{80}) || !reflect.DeepEqual(h.Services, []string{"http"}) ||
			!reflect.DeepEqual(h.Technologies, []string{"nginx"}) || !reflect.DeepEqual(h.FindingKinds, []string{"admin-panel"}) ||
			!reflect.DeepEqual(h.Titles, []string{"Intranet portal"}) || !reflect.DeepEqual(h.Hostnames, []string{}) ||
			h.FirstSeen.IsZero() || h.LastSeen.Before(h.FirstSeen) {
			t.Errorf("row = %+v", h)
		}
		p, err = inv.ListHosts(ctx, HostQuery{Status: "unstable", Sort: "address"})
		if err != nil || len(p.Hosts) != 2 || p.Hosts[0].MissedRuns != 1 || math.Abs(p.Hosts[0].Stability-2.0/3) > 1e-9 ||
			p.Hosts[0].InterestScore != 20+10+10 {
			t.Errorf("unstable rows = %+v, %v", p.Hosts, err)
		}
	})

	t.Run("user edits are visible at once", func(t *testing.T) {
		if err := inv.UpdateHostUserFields(ctx, "10.0.0.2", HostUserFields{Tags: []string{"fresh"}, DisplayName: "Zed"}); err != nil {
			t.Fatalf("UpdateHostUserFields: %v", err)
		}
		p, err := inv.ListHosts(ctx, HostQuery{Tag: "fresh"})
		if err != nil || len(p.Hosts) != 1 || p.Hosts[0].Address != "10.0.0.2" || p.Hosts[0].DisplayName != "Zed" {
			t.Errorf("ListHosts(tag fresh) = %+v, %v", p, err)
		}
	})

	t.Run("whitelist", func(t *testing.T) {
		for _, q := range []HostQuery{
			{Sort: "interest_score"},
			{Sort: "address; DROP TABLE hosts"},
			{Sort: "s.address"},
			{Status: "bogus"},
			{Status: "active' OR '1'='1"},
			{Status: "ACTIVE"},
			{Port: -1},
			{Port: 65536},
		} {
			p, err := inv.ListHosts(ctx, q)
			if !errors.Is(err, ErrInvalidQuery) {
				t.Errorf("ListHosts(%+v) = %+v, %v; want ErrInvalidQuery", q, p, err)
			}
		}
		p, err := inv.ListHosts(ctx, HostQuery{})
		if err != nil || p.Total != 12 {
			t.Errorf("after rejected queries ListHosts = total %d, %v; want 12", p.Total, err)
		}
	})
}

func seedHosts20000(t *testing.T, inv *Inventory, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	var runIDs []int64
	for i := 1; i <= 3; i++ {
		runIDs = append(runIDs, mustRun(t, inv, fmt.Sprintf("p%d", i), 2).ID)
	}
	notAfterFar := time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	notAfterSoon := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	names := make([][]byte, 20000)
	for i := 0; i < len(names); i += 17 {
		sealed, err := inv.sealString(fmt.Sprintf("host %d", i))
		if err != nil {
			t.Fatal(err)
		}
		names[i] = sealed
	}
	stmts := []struct {
		name string
		sql  string
		args []any
	}{
		{"seed table", `CREATE TABLE seed_hosts AS
			SELECT i, '10.' || (i / 65536) || '.' || (i / 256 % 256) || '.' || (i % 256) AS address, i / 256 AS grp
			FROM generate_series(0, 19999) i`, nil},
		{"seed runs", `CREATE TABLE seed_runs AS SELECT r, ord FROM unnest($1::bigint[]) WITH ORDINALITY AS u(r, ord)`, []any{runIDs}},
		{"seen", `CREATE TABLE seed_seen AS SELECT h.i, h.grp, sr.r FROM seed_hosts h, seed_runs sr
			WHERE sr.ord = 1 OR (sr.ord = 2 AND h.i % 5 <> 0) OR (sr.ord = 3 AND h.i % 10 <> 0 AND h.i % 7 <> 3)`, nil},
		{"groups", `INSERT INTO run_groups (run_id, group_index, address_count, hosts_found)
			SELECT sr.r, g, 256, 256 FROM seed_runs sr, generate_series(0, 19999 / 256) g`, nil},
		{"coverage", `INSERT INTO run_group_addresses (run_id, group_index, address)
			SELECT sr.r, h.grp, h.address FROM seed_hosts h, seed_runs sr`, nil},
		{"hosts", `INSERT INTO hosts (address, tags, display_name)
			SELECT address,
			       CASE WHEN i % 10 = 1 THEN ARRAY['dmz'] WHEN i % 25 = 2 THEN ARRAY['crown-jewel', 'dmz'] ELSE '{}' END,
			       ($1::bytea[])[i + 1]
			FROM seed_hosts ORDER BY i`, []any{names}},
		{"host observations", `INSERT INTO host_observations (run_id, group_index, host_id, hostnames)
			SELECT ss.r, ss.grp, ho.id, CASE WHEN ss.i % 3 = 0 THEN ARRAY['h' || ss.i || '.example'] ELSE '{}' END
			FROM seed_seen ss JOIN seed_hosts h ON h.i = ss.i JOIN hosts ho ON ho.address = h.address`, nil},
		{"services", `INSERT INTO services (host_id, port, protocol)
			SELECT ho.id, (ARRAY[80, 443, 22, 8080])[k + 1], 'tcp'
			FROM seed_hosts h JOIN hosts ho ON ho.address = h.address, generate_series(0, 3) k WHERE k <= h.i % 4
			UNION ALL
			SELECT ho.id, 23, 'tcp' FROM seed_hosts h JOIN hosts ho ON ho.address = h.address WHERE h.i % 11 = 0`, nil},
		{"service observations", `INSERT INTO service_observations (run_id, group_index, service_id, state, service, product, http)
			SELECT ss.r, ss.grp, sv.id, 'open',
			       CASE sv.port WHEN 22 THEN 'ssh' WHEN 23 THEN 'telnet' ELSE 'http' END, '',
			       CASE WHEN sv.port IN (80, 443, 8080) THEN jsonb_build_object(
			           'scheme', CASE sv.port WHEN 443 THEN 'https' ELSE 'http' END,
			           'url', 'http://' || h.address || ':' || sv.port || '/', 'status_code', 200,
			           'title', 'Service ' || ss.i, 'redirect_chain', '[]'::jsonb,
			           'tls', CASE WHEN sv.port = 443 THEN jsonb_build_object('self_signed', ss.i % 3 = 0,
			               'not_after', CASE WHEN ss.i % 13 = 0 THEN $1 ELSE $2 END) END) END
			FROM seed_seen ss JOIN seed_hosts h ON h.i = ss.i JOIN hosts ho ON ho.address = h.address
			JOIN services sv ON sv.host_id = ho.id`, []any{notAfterSoon, notAfterFar}},
		{"technologies", `INSERT INTO technologies (service_observation_id, ordinal, name, confidence, source)
			SELECT so.id, 0, (ARRAY['nginx', 'Apache', 'WordPress', 'PHP', 'IIS'])[abs(hashtext(so.service_id::text)) % 5 + 1], 90, 'builtin'
			FROM service_observations so WHERE so.http IS NOT NULL`, nil},
		{"findings", `INSERT INTO findings (service_observation_id, ordinal, signature_id, kind, confidence)
			SELECT so.id, 0, k.kind || '-sig', k.kind, 80
			FROM service_observations so JOIN services sv ON sv.id = so.service_id
			JOIN LATERAL (SELECT CASE WHEN sv.host_id % 50 = 0 THEN 'admin-panel' WHEN sv.host_id % 70 = 1 THEN 'staging'
			                          WHEN sv.host_id % 90 = 2 THEN 'iot' WHEN sv.host_id % 30 = 3 THEN 'interesting-header'
			                          WHEN sv.host_id % 40 = 4 THEN 'interesting-cookie' END AS kind) k ON k.kind IS NOT NULL
			WHERE sv.port = 80`, nil},
		{"analyze", `ANALYZE`, nil},
	}
	for _, st := range stmts {
		if _, err := s.Pool.Exec(ctx, st.sql, st.args...); err != nil {
			t.Fatalf("seed %s: %v", st.name, err)
		}
	}
	start := time.Now()
	if err := inv.RefreshSummary(ctx); err != nil {
		t.Fatalf("RefreshSummary: %v", err)
	}
	t.Logf("RefreshSummary of 20000 hosts took %v", time.Since(start))
}

func TestListHostsPerformance20000(t *testing.T) {
	ctx := context.Background()
	inv, s := openInventory(t)
	seedHosts20000(t, inv, s)

	all, err := inv.ListHosts(ctx, HostQuery{})
	if err != nil || all.Total != 20000 {
		t.Fatalf("ListHosts() total = %d, %v; want 20000", all.Total, err)
	}
	const budget = 300 * time.Millisecond
	interest := func(q HostQuery) HostQuery { q.Sort, q.Desc, q.PerPage = "interest", true, 50; return q }
	cases := []struct {
		name string
		q    HostQuery
	}{
		{"no filter, interest desc", interest(HostQuery{})},
		{"no filter, address", HostQuery{PerPage: 50}},
		{"no filter, last page", HostQuery{PerPage: 50, Page: 400}},
		{"status unstable", interest(HostQuery{Status: "unstable"})},
		{"status inactive", interest(HostQuery{Status: "inactive"})},
		{"port 443", interest(HostQuery{Port: 443})},
		{"port 23", interest(HostQuery{Port: 23})},
		{"service ssh", interest(HostQuery{Service: "ssh"})},
		{"technology WordPress", interest(HostQuery{Technology: "WordPress"})},
		{"finding kind admin-panel", interest(HostQuery{FindingKind: "admin-panel"})},
		{"tag dmz", interest(HostQuery{Tag: "dmz"})},
		{"free text broad", interest(HostQuery{Text: "example"})},
		{"free text narrow", interest(HostQuery{Text: "service 1234"})},
		{"combined", interest(HostQuery{Status: "active", Port: 443, Technology: "nginx", Tag: "dmz", Text: "service"})},
		{"display name sort", HostQuery{Sort: "display_name", Desc: true, PerPage: 50}},
	}
	for _, c := range cases {
		start := time.Now()
		p, err := inv.ListHosts(ctx, c.q)
		d := time.Since(start)
		if err != nil {
			t.Fatalf("%s: ListHosts: %v", c.name, err)
		}
		t.Logf("%-28s %8.2f ms  total %5d  page %d", c.name, float64(d.Microseconds())/1000, p.Total, len(p.Hosts))
		if p.Total == 0 || len(p.Hosts) != min(50, p.Total) {
			t.Errorf("%s: total %d with %d rows; the seed should match this filter", c.name, p.Total, len(p.Hosts))
		}
		if d >= budget {
			t.Errorf("%s: ListHosts took %v, budget %v", c.name, d, budget)
		}
	}
}

func TestBackfillSummary(t *testing.T) {
	ctx := context.Background()
	inv, s := openInventory(t)
	const A, B, C = "10.4.0.1", "10.4.0.2", "10.4.0.3"
	web := HostResult{Address: A, Services: []ServiceResult{{Port: 80, Protocol: "tcp", State: "open", Service: "http"}}}
	ssh := HostResult{Address: B, Services: []ServiceResult{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}}
	r1 := mustRun(t, inv, "b1", 1)
	mustRecord(t, inv, r1, GroupResult{Index: 0, Addresses: []string{A, B, C}, Hosts: []HostResult{web, ssh}})
	old := readSummary(t, s)
	r2 := mustRun(t, inv, "b2", 1)
	ssh.Services = append(ssh.Services, ServiceResult{Port: 443, Protocol: "tcp", State: "open", Service: "https"})
	mustRecord(t, inv, r2, GroupResult{Index: 0, Addresses: []string{A, B, C}, Hosts: []HostResult{web, ssh}})
	want := readSummary(t, s)

	if n, err := inv.BackfillSummary(ctx); err != nil || n != 0 {
		t.Fatalf("BackfillSummary on a current summary = %d, %v; want 0, nil", n, err)
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM host_summary WHERE address = $1`, A); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE host_summary SET last_run_id = $2, ports = $3 WHERE address = $1`,
		B, r1.ID, old[B].Ports); err != nil {
		t.Fatal(err)
	}
	n, err := inv.BackfillSummary(ctx)
	if err != nil || n != 2 {
		t.Fatalf("BackfillSummary = %d, %v; want 2 (one missing, one stale)", n, err)
	}
	if got := readSummary(t, s); !reflect.DeepEqual(got, want) {
		t.Errorf("backfilled summary:\nwant %+v\ngot  %+v", want, got)
	}
	if n, err := inv.BackfillSummary(ctx); err != nil || n != 0 {
		t.Fatalf("second BackfillSummary = %d, %v; want 0, nil", n, err)
	}
	page, err := inv.ListHosts(ctx, HostQuery{Port: 443})
	if err != nil || page.Total != 1 || page.Hosts[0].Address != B {
		t.Fatalf("ListHosts port 443 after backfill = %+v, %v", page, err)
	}
}

func TestHostListFollowsEveryWritePath(t *testing.T) {
	ctx := context.Background()
	inv, _ := openInventory(t)
	const A, B = "10.5.0.1", "10.5.0.2"
	r := mustRun(t, inv, "w1", 1)
	cases := []struct {
		path  string
		write func() error
		query HostQuery
		want  string
	}{
		{"scan group", func() error {
			return inv.RecordGroup(ctx, r.ID, GroupResult{Index: 0, Addresses: []string{A, B},
				Hosts: []HostResult{{Address: A, Services: []ServiceResult{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}}}})
		}, HostQuery{Service: "ssh"}, A},
		{"late host", func() error {
			return inv.RecordLateHosts(ctx, r.ID, []HostResult{{Address: B,
				Services: []ServiceResult{{Port: 8080, Protocol: "tcp", State: "open", Service: "http"}}}})
		}, HostQuery{Port: 8080}, B},
		{"analyst tag edit", func() error {
			return inv.EditHostUserFields(ctx, Editor{Username: "ana", Addr: "local"}, B, HostUserFields{Tags: []string{"dmz"}})
		}, HostQuery{Tag: "dmz"}, B},
	}
	for _, c := range cases {
		if err := c.write(); err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		page, err := inv.ListHosts(ctx, c.query)
		if err != nil || page.Total != 1 || page.Hosts[0].Address != c.want {
			t.Errorf("%s: ListHosts(%+v) = %+v, %v; want only %s", c.path, c.query, page, err, c.want)
		}
	}
}
