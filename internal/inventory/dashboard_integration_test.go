//go:build integration

package inventory

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"asi/internal/probe"
)

func dashboardScenario(t *testing.T, inv *Inventory) (Run, Run) {
	t.Helper()
	far := time.Now().Add(400 * 24 * time.Hour).UTC().Truncate(time.Second)
	soon := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	https := func(port int, title string, selfSigned bool, notAfter time.Time, kind string) ServiceResult {
		s := ServiceResult{Port: port, Protocol: "tcp", State: "open", Service: "http",
			HTTP: &probe.HTTP{Scheme: "https", StatusCode: 200, Title: title,
				TLS: &probe.TLS{SubjectCN: title + ".example", IssuerCN: "CA", NotAfter: notAfter.Format(time.RFC3339), SelfSigned: selfSigned}}}
		if kind != "" {
			s.Findings = []Finding{{SignatureID: kind + "-sig", Kind: kind, Name: kind + " finding", Confidence: 80}}
		}
		return s
	}
	http := func(title, kind string) ServiceResult {
		s := ServiceResult{Port: 80, Protocol: "tcp", State: "open", Service: "http", HTTP: &probe.HTTP{Scheme: "http", StatusCode: 200, Title: title}}
		if kind != "" {
			s.Findings = []Finding{{SignatureID: kind + "-sig", Kind: kind, Name: kind + " finding", Confidence: 70}}
		}
		return s
	}
	ssh := ServiceResult{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}
	a1 := HostResult{Address: "10.4.0.1", Services: []ServiceResult{https(443, "panel", true, far, "admin-panel"), ssh}}
	a2 := HostResult{Address: "10.4.0.1", Services: []ServiceResult{https(443, "panel", true, far, "admin-panel")}}
	b1 := HostResult{Address: "10.4.0.2", Services: []ServiceResult{http("Staging v1", "staging")}}
	b2 := HostResult{Address: "10.4.0.2", Services: []ServiceResult{http("Staging v2", "staging")}}
	c := HostResult{Address: "10.4.0.3", Services: []ServiceResult{http("Camera", "iot")}}
	d := HostResult{Address: "10.4.0.4", Services: []ServiceResult{https(8443, "billing", false, soon, "")}}
	e := HostResult{Address: "10.4.0.5", Services: []ServiceResult{http("New admin", "admin-panel")}}
	all := []string{"10.4.0.1", "10.4.0.2", "10.4.0.3", "10.4.0.4", "10.4.0.5"}

	r1 := mustRun(t, inv, "d1", 2)
	mustRecord(t, inv, r1, GroupResult{Index: 0, Addresses: all, Hosts: []HostResult{a1, b1, c, d}})
	if err := inv.SetRunStatus(context.Background(), r1.ID, RunCompleted); err != nil {
		t.Fatal(err)
	}
	r2 := mustRun(t, inv, "d2", 2)
	mustRecord(t, inv, r2, GroupResult{Index: 0, Addresses: all, Hosts: []HostResult{a2, b2, d, e}})
	return r1, r2
}

func TestDashboard(t *testing.T) {
	ctx := context.Background()
	inv, _ := openInventory(t)

	empty, err := inv.Dashboard(ctx, time.Now())
	if err != nil {
		t.Fatalf("Dashboard on an empty database: %v", err)
	}
	if empty.Hosts != (StatusCounts{}) || len(empty.TopHosts) != 0 || len(empty.Findings) != 0 || len(empty.Certs) != 0 || empty.Latest != nil {
		t.Errorf("empty dashboard = %+v", empty)
	}

	_, r2 := dashboardScenario(t, inv)
	d, err := inv.Dashboard(ctx, time.Now())
	if err != nil {
		t.Fatalf("Dashboard: %v", err)
	}
	if d.Hosts != (StatusCounts{Active: 4, Unstable: 1}) {
		t.Errorf("host counts = %+v, want 4 active, 1 unstable", d.Hosts)
	}
	var top []string
	var scores []int
	for _, h := range d.TopHosts {
		top, scores = append(top, h.Address), append(scores, h.InterestScore)
	}
	if want := []string{"10.4.0.1", "10.4.0.5", "10.4.0.3", "10.4.0.2", "10.4.0.4"}; !reflect.DeepEqual(top, want) ||
		!reflect.DeepEqual(scores, []int{50, 50, 35, 30, 20}) {
		t.Errorf("top hosts = %v %v", top, scores)
	}
	var findings []string
	for _, f := range d.Findings {
		findings = append(findings, f.Address+" "+f.Kind)
	}
	if want := []string{"10.4.0.5 admin-panel", "10.4.0.1 admin-panel", "10.4.0.2 staging", "10.4.0.3 iot"}; !reflect.DeepEqual(findings, want) {
		t.Errorf("findings = %v, want %v (newest first)", findings, want)
	}
	if f := d.Findings[0]; f.Port != 80 || f.Name != "admin-panel finding" || f.SignatureID != "admin-panel-sig" || f.FirstSeen.IsZero() {
		t.Errorf("newest finding = %+v", f)
	}
	if len(d.Certs) != 2 || d.Certs[0].Address != "10.4.0.4" || d.Certs[0].SelfSigned || d.Certs[0].Subject != "billing.example" ||
		time.Until(d.Certs[0].NotAfter) > 11*24*time.Hour || d.Certs[1].Address != "10.4.0.1" || !d.Certs[1].SelfSigned || d.Certs[1].Port != 443 {
		t.Errorf("certificates = %+v", d.Certs)
	}
	p := d.Latest
	if p == nil || p.Run.Name != "d2" || p.Run.Status != RunRunning || p.Groups != 1 || p.Addresses != 5 || p.HostsFound != 4 ||
		p.PreviousRun != "d1" || p.LastGroupAt == nil || p.ChangesVersion == "" {
		t.Fatalf("progress = %+v", p)
	}

	mustRecord(t, inv, r2, GroupResult{Index: 1, Addresses: []string{"10.4.0.9"}})
	again, err := inv.Dashboard(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if again.Latest.Groups != 2 || again.Latest.Addresses != 6 || again.Latest.ChangesVersion == p.ChangesVersion {
		t.Errorf("progress after another group = %+v (version %q, before %q)", again.Latest, again.Latest.ChangesVersion, p.ChangesVersion)
	}
	if err := inv.SetRunStatus(ctx, r2.ID, RunCompleted); err != nil {
		t.Fatal(err)
	}
	done, _ := inv.Dashboard(ctx, time.Now())
	if done.Latest.Run.Status != RunCompleted || done.Latest.Run.FinishedAt == nil {
		t.Errorf("completed run = %+v", done.Latest.Run)
	}
}

// REQ-INVENTORY-034
func TestDashboardNeedsAttention(t *testing.T) {
	ctx := context.Background()
	inv, db := openInventory(t)
	_, r2 := dashboardScenario(t, inv)
	d, err := inv.Dashboard(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.NewPanels) != 1 || d.NewPanels[0].Address != "10.4.0.5" || d.NewPanels[0].Port != 80 || d.NewPanels[0].Kind != "admin-panel" {
		t.Errorf("new admin panels = %+v, want only 10.4.0.5 (10.4.0.1 had its panel in d1)", d.NewPanels)
	}
	if len(d.Slow) != 0 {
		t.Errorf("slow services without timings = %+v", d.Slow)
	}
	if d.Setup != (Setup{HasCompletedRun: true}) {
		t.Errorf("setup = %+v, want only a completed run", d.Setup)
	}
	if err := inv.SetRunStatus(ctx, r2.ID, RunCompleted); err != nil {
		t.Fatal(err)
	}

	timed := func(ms int64) ServiceResult {
		return ServiceResult{Port: 80, Protocol: "tcp", State: "open", Service: "http", HTTP: &probe.HTTP{Scheme: "http", StatusCode: 200, ResponseMS: ms}}
	}
	hosts := []string{"10.6.0.1", "10.6.0.2", "10.6.0.3"}
	for i, ms := range [][3]int64{{100, 400, 100}, {120, 400, 100}, {900, 600, 450}} {
		run := mustRun(t, inv, fmt.Sprintf("t%d", i), 2)
		var hs []HostResult
		for j, a := range hosts {
			hs = append(hs, HostResult{Address: a, Services: []ServiceResult{timed(ms[j])}})
		}
		mustRecord(t, inv, run, GroupResult{Index: 0, Addresses: hosts, Hosts: hs})
		if err := inv.SetRunStatus(ctx, run.ID, RunCompleted); err != nil {
			t.Fatal(err)
		}
	}
	d, err = inv.Dashboard(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Slow) != 1 || d.Slow[0] != (SlowService{Address: "10.6.0.1", Port: 80, Protocol: "tcp", LatestMS: 900, MedianMS: 120}) {
		t.Errorf("slow services = %+v, want only 10.6.0.1 (600 ms is not 3x its 400 ms median, 450 ms is under %d ms)", d.Slow, SlowMinMS)
	}
	if len(d.NewPanels) != 0 {
		t.Errorf("new admin panels in a run without findings = %+v", d.NewPanels)
	}

	if _, err := db.Pool.Exec(ctx, `INSERT INTO scan_definitions (name, inactive_after, settings, schedule) VALUES ('weekly', 2, '{}', '{}')`); err != nil {
		t.Fatal(err)
	}
	if d, _ = inv.Dashboard(ctx, time.Now()); d.Setup != (Setup{HasScan: true, HasCompletedRun: true}) {
		t.Errorf("setup after a scan definition = %+v", d.Setup)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO roles (name) VALUES ('auditor')`); err != nil {
		t.Fatal(err)
	}
	if d, _ = inv.Dashboard(ctx, time.Now()); !d.Setup.Done() {
		t.Errorf("setup after a custom role = %+v", d.Setup)
	}
}

func TestDashboardLatestRunIgnoresRunsThatNeverStartedScanning(t *testing.T) {
	ctx := context.Background()
	inv, _ := openInventory(t)
	_, r2 := dashboardScenario(t, inv)
	if err := inv.SetRunStatus(ctx, r2.ID, RunCompleted); err != nil {
		t.Fatal(err)
	}
	never := mustRun(t, inv, "never-started", 2)
	if err := inv.SetRunStatus(ctx, never.ID, RunFailed); err != nil {
		t.Fatal(err)
	}
	d, err := inv.Dashboard(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if d.Latest == nil || d.Latest.Run.Name != "d2" || d.Latest.PreviousRun != "d1" {
		t.Fatalf("latest = %+v, want d2 after d1: a failed run without groups never scanned", d.Latest)
	}

	partial := mustRun(t, inv, "failed-later", 2)
	mustRecord(t, inv, partial, GroupResult{Index: 0, Addresses: []string{"10.4.0.9"}})
	if err := inv.SetRunStatus(ctx, partial.ID, RunFailed); err != nil {
		t.Fatal(err)
	}
	if d, err = inv.Dashboard(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if d.Latest == nil || d.Latest.Run.Name != "failed-later" || d.Latest.PreviousRun != "d2" {
		t.Fatalf("latest = %+v, want failed-later after d2: it recorded a group before failing", d.Latest)
	}
}
