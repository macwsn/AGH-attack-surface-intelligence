//go:build integration

package web

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"asi/internal/inventory"
)

func recheckRun(t *testing.T, inv *inventory.Inventory, name string, addrs []string, hosts []inventory.HostResult) inventory.Run {
	t.Helper()
	ctx := context.Background()
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name, InactiveAfter: 2, Source: inventory.SourceScan,
		Settings: inventory.RunSettings{Targets: addrs, Workers: 1, Mode: inventory.ModeRecheck}})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: addrs, Hosts: hosts}); err != nil {
		t.Fatal(err)
	}
	if err := inv.SetRunStatus(ctx, run.ID, inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
	return run
}

// REQ-WEB-009: AC2 of CP1 of T-803xb7cwjk
func TestDashboardChangePairSelection(t *testing.T) {
	ssh := inventory.ServiceResult{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}
	web := inventory.ServiceResult{Port: 80, Protocol: "tcp", State: "open", Service: "http"}
	all := []string{"10.62.0.1", "10.62.0.2"}
	one := []inventory.HostResult{{Address: "10.62.0.1", Services: []inventory.ServiceResult{ssh}}}
	two := []inventory.HostResult{{Address: "10.62.0.1", Services: []inventory.ServiceResult{ssh}}, {Address: "10.62.0.2", Services: []inventory.ServiceResult{web}}}
	newHost := regexp.MustCompile(`<span>New hosts</span><progress class="bar new" max="\d+" value="1"></progress><span class="num">1</span>`)
	pair := `Scan <a href="/runs/\d+">scan-b</a> against scan <a href="/runs/\d+">scan-a</a>`

	for _, tc := range []struct {
		name     string
		seed     func(*testing.T, *inventory.Inventory)
		want     []string
		wantRe   []string
		mustNot  []string
		wantBars bool
	}{
		{
			name: "recheck after the scan keeps the pair",
			seed: func(t *testing.T, inv *inventory.Inventory) {
				truthRun(t, inv, "scan-a", inventory.SourceScan, inventory.RunCompleted, all, one)
				truthRun(t, inv, "scan-b", inventory.SourceScan, inventory.RunCompleted, all, two)
				recheckRun(t, inv, "recheck-c", []string{"10.62.0.1"}, one)
			},
			want:     []string{"<dt>Latest recheck</dt>", ">recheck-c</a>", `href="/changes?from=scan-a&amp;to=scan-b"`, `href="/hosts/10.62.0.2"`},
			wantRe:   []string{pair},
			mustNot:  []string{"Running now"},
			wantBars: true,
		},
		{
			name: "failed scan is skipped",
			seed: func(t *testing.T, inv *inventory.Inventory) {
				truthRun(t, inv, "scan-a", inventory.SourceScan, inventory.RunCompleted, all, one)
				truthRun(t, inv, "scan-b", inventory.SourceScan, inventory.RunCompleted, all, two)
				truthRun(t, inv, "scan-failed", inventory.SourceScan, inventory.RunFailed, all, one)
			},
			want:     []string{`href="/hosts/10.62.0.2"`},
			wantRe:   []string{pair},
			mustNot:  []string{">scan-failed</a>", "Running now"},
			wantBars: true,
		},
		{
			name: "one completed scan waits for the second",
			seed: func(t *testing.T, inv *inventory.Inventory) {
				truthRun(t, inv, "scan-a", inventory.SourceScan, inventory.RunCompleted, all, one)
				truthRun(t, inv, "import-x", inventory.SourceImport, inventory.RunCompleted, all, two)
				truthRun(t, inv, "scan-live", inventory.SourceScan, inventory.RunRunning, all, nil)
			},
			want:    []string{"Changes appear after the second scan. Scan scan-a is the only completed scan so far.", "<dt>Latest import</dt>", ">import-x</a>", "<dt>Running now</dt>", ">scan-live</a>"},
			mustNot: []string{"No changes", "Changes appear after the second run.", `href="/changes?`},
		},
		{
			name: "identical scans say so",
			seed: func(t *testing.T, inv *inventory.Inventory) {
				truthRun(t, inv, "scan-a", inventory.SourceScan, inventory.RunCompleted, all, two)
				truthRun(t, inv, "scan-b", inventory.SourceScan, inventory.RunCompleted, all, two)
				truthRun(t, inv, "manual-y", inventory.SourceManual, inventory.RunCompleted, []string{"10.62.0.2"}, two[1:])
			},
			want:    []string{"No changes since run scan-a.", "<dt>Latest manual entry</dt>", ">manual-y</a>", `href="/changes?from=scan-a&amp;to=scan-b"`},
			wantRe:  []string{pair},
			mustNot: []string{"Changes appear after"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv, _, h, fa := truthSite(t)
			tc.seed(t, inv)
			rec := do(h, http.MethodGet, "/", nil, fa.session(t, "alice"))
			body := rec.Body.String()
			if rec.Code != http.StatusOK {
				t.Fatalf("GET / = %d:\n%s", rec.Code, body)
			}
			panel := section(body, "Changes in the latest run")
			if regexp.MustCompile(`style\s*=`).MatchString(panel) {
				t.Errorf("change panel uses inline styles")
			}
			if got := newHost.MatchString(panel); got != tc.wantBars {
				t.Errorf("New hosts = 1 bar shown = %v, want %v:\n%s", got, tc.wantBars, panel)
			}
			for _, want := range tc.want {
				if !strings.Contains(panel, want) {
					t.Errorf("change panel lacks %q:\n%s", want, panel)
				}
			}
			for _, re := range tc.wantRe {
				if !regexp.MustCompile(re).MatchString(panel) {
					t.Errorf("change panel does not match %q:\n%s", re, panel)
				}
			}
			for _, bad := range tc.mustNot {
				if strings.Contains(panel, bad) {
					t.Errorf("change panel shows %q:\n%s", bad, panel)
				}
			}
		})
	}
}
