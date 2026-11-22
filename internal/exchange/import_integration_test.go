//go:build integration

package exchange_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"testing"
	"time"

	"asi/internal/detect"
	"asi/internal/diff"
	"asi/internal/exchange"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func openInventory(t *testing.T) (*inventory.Inventory, *store.Store) {
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
		t.Fatal(err)
	}
	k, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.New(s, k), s
}

func scanRun(t *testing.T, inv *inventory.Inventory, name string, hosts ...inventory.HostResult) {
	t.Helper()
	ctx := context.Background()
	r, err := inv.CreateRun(ctx, inventory.RunSpec{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.RecordGroup(ctx, r.ID, inventory.GroupResult{Hosts: hosts}); err != nil {
		t.Fatal(err)
	}
	if err := inv.SetRunStatus(ctx, r.ID, inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
}

func exportOf(t *testing.T, inv *inventory.Inventory, run string) inventory.Export {
	t.Helper()
	exp, err := inv.Export(context.Background(), run)
	if err != nil {
		t.Fatalf("Export %q: %v", run, err)
	}
	return exp
}

func exportJSON(t *testing.T, exp inventory.Export) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(exp); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func apply(t *testing.T, inv *inventory.Inventory, format string, data []byte, opts exchange.Options) exchange.Report {
	t.Helper()
	b, err := exchange.Parse(format, data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	rep, err := exchange.Apply(context.Background(), inv, b, opts)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return rep
}

func comparable(exp inventory.Export) []inventory.ExportHost {
	var hosts []inventory.ExportHost
	if err := json.Unmarshal(exportJSONRaw(exp), &hosts); err != nil {
		panic(err)
	}
	for i := range hosts {
		hosts[i].FirstSeen, hosts[i].LastSeen, hosts[i].InterestScore, hosts[i].Availability = time.Time{}, time.Time{}, 0, nil
		for j := range hosts[i].Services {
			hosts[i].Services[j].FirstSeen, hosts[i].Services[j].LastSeen = time.Time{}, time.Time{}
		}
	}
	return hosts
}

func exportJSONRaw(exp inventory.Export) []byte {
	b, err := json.Marshal(exp.Hosts)
	if err != nil {
		panic(err)
	}
	return b
}

func shopSignatures(t *testing.T) *detect.Set {
	t.Helper()
	sigs, err := detect.Parse([]byte(`
- id: shop-title
  name: Shop
  kind: technology
  category: e-commerce
  confidence: 70
  match: { all: [ { type: title_regex, value: 'Shop v' } ] }
  version: { type: title_regex, value: 'Shop v([0-9.]+)', group: 1 }
`))
	if err != nil {
		t.Fatal(err)
	}
	return &detect.Set{Signatures: sigs}
}

func richHost() inventory.HostResult {
	return inventory.HostResult{Address: "172.30.0.12", Hostnames: []string{"admin.example", "www.example"}, Services: []inventory.ServiceResult{
		{Port: 22, Protocol: "tcp", State: "open", Service: "ssh", Product: "OpenSSH", Version: "9.6"},
		{Port: 443, Protocol: "tcp", State: "open", Service: "http", Product: "nginx", Version: "1.27.5",
			HTTP: &probe.HTTP{Scheme: "https", URL: "https://172.30.0.12/", StatusCode: 200, Title: "Shop v2.1",
				Headers:       map[string]string{"server": "nginx/1.27.5", "x-debug-token": "abc"},
				Cookies:       []probe.Cookie{{Name: "sid", HTTPOnly: true, SameSite: "Lax"}},
				RedirectChain: []string{"https://172.30.0.12/shop/"},
				TLS:           &probe.TLS{SubjectCN: "admin.example", IssuerCN: "admin.example", SANs: []string{"admin.example"}, SHA256: "ab12", SelfSigned: true},
				FaviconSHA256: "cd34", FaviconMMH3: -123},
			Technologies: []inventory.Technology{
				{Name: "Shop", Category: "e-commerce", Version: "2.1", Confidence: 70, Source: "signature:shop-title"},
				{Name: "nginx", Category: "web-server", Version: "1.27.5", Confidence: 90, Source: "builtin"}},
			Findings: []inventory.Finding{
				{SignatureID: "shop-title", Kind: "technology", Name: "Shop", Version: "2.1", Confidence: 70, Evidence: "GET /: title matches"},
				{SignatureID: "debug-token-header", Kind: "interesting-header", Name: "Debug token", Confidence: 60, Evidence: "GET /: header x-debug-token"}}},
	}}
}

// REQ-EXCHANGE-006 AC5: export json -> import into an empty database -> export json gives the same hosts, services, technologies and findings.
func TestJSONRoundTripIntoEmptyDatabase(t *testing.T) {
	ctx := context.Background()
	src, _ := openInventory(t)
	scanRun(t, src, "s1", richHost(), inventory.HostResult{Address: "172.30.0.13"})
	if err := src.UpdateHostUserFields(ctx, "172.30.0.12", inventory.HostUserFields{Tags: []string{"crown-jewel", "dmz"},
		Notes: "ask the web team", Owner: "web", Criticality: "high"}); err != nil {
		t.Fatal(err)
	}
	first := exportOf(t, src, "")

	dst, _ := openInventory(t)
	rep := apply(t, dst, "json", exportJSON(t, first), exchange.Options{Signatures: shopSignatures(t)})
	if rep.Hosts != 2 || rep.Services != 2 || len(rep.Errors) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	second := exportOf(t, dst, "")
	if got, want := comparable(second), comparable(first); !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip differs\n got %s\nwant %s", exportJSONRaw(inventory.Export{Hosts: got}), exportJSONRaw(inventory.Export{Hosts: want}))
	}
	if second.Run != rep.Run {
		t.Errorf("export run = %q, want the import run %q", second.Run, rep.Run)
	}

	again, _ := openInventory(t)
	apply(t, again, "json", exportJSON(t, second), exchange.Options{})
	if got, want := comparable(exportOf(t, again, "")), comparable(second); !reflect.DeepEqual(got, want) {
		t.Fatalf("second round trip differs")
	}
}

func hostWeb(addr, title string, ports ...int) inventory.HostResult {
	h := inventory.HostResult{Address: addr}
	for _, p := range ports {
		s := inventory.ServiceResult{Port: p, Protocol: "tcp", State: "open", Service: "ssh"}
		if p == 80 {
			s.Service, s.HTTP = "http", &probe.HTTP{Scheme: "http", StatusCode: 200, Title: title}
		}
		h.Services = append(h.Services, s)
	}
	return h
}

func changeSet(d diff.Diff) map[string]bool {
	out := map[string]bool{}
	for _, c := range d.Changes {
		key := c.Type + " " + c.Address
		if c.Port != nil {
			key += " " + c.Protocol
		}
		for _, f := range c.Fields {
			key += " " + f.Field
		}
		out[key] = true
	}
	return out
}

// REQ-EXCHANGE-003 REQ-EXCHANGE-004 REQ-INVENTORY-019 AC1 AC3: an import is a run of source import that takes part in diffs; a dry run predicts it and records nothing.
func TestImportRunTakesPartInDiffsAndDryRunRecordsNothing(t *testing.T) {
	ctx := context.Background()
	inv, st := openInventory(t)
	scanRun(t, inv, "s1", hostWeb("10.0.0.1", "Intranet v1", 22, 80), hostWeb("10.0.0.2", "", 22))
	data := []byte(`{"schema":"asi.export/v1","hosts":[
		{"address":"10.0.0.1","services":[{"port":80,"protocol":"tcp","state":"open","service":"http","http":{"scheme":"http","status_code":200,"title":"Intranet v2"}}]},
		{"address":"10.0.0.3"},
		{"address":"10.0.0.999"}]}`)
	want := map[string]bool{
		"service_changed 10.0.0.1 tcp http.title": true,
		"service_missing 10.0.0.1 tcp":            true,
		"host_new 10.0.0.3":                       true,
	}
	count := func() int {
		var n int
		if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM runs`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	dry := apply(t, inv, "json", data, exchange.Options{Name: "imp", DryRun: true})
	if !dry.DryRun || count() != 1 {
		t.Fatalf("dry run recorded something: runs %d report %+v", count(), dry)
	}
	if got := changeSet(dry.Changes); !reflect.DeepEqual(got, want) {
		t.Errorf("dry run changes = %v, want %v", got, want)
	}
	if len(dry.Errors) != 1 || dry.Errors[0].Row != 3 {
		t.Errorf("dry run errors = %+v", dry.Errors)
	}

	rep := apply(t, inv, "json", data, exchange.Options{Name: "imp"})
	run, err := inv.RunByName(ctx, "imp")
	if err != nil {
		t.Fatal(err)
	}
	if run.Source != inventory.SourceImport || run.Status != inventory.RunCompleted {
		t.Fatalf("import run = %+v", run)
	}
	if got := changeSet(rep.Changes); !reflect.DeepEqual(got, want) {
		t.Errorf("import changes = %v, want %v", got, want)
	}
	if got := changeSet(diff.Compute(exportOf(t, inv, "s1"), exportOf(t, inv, "imp"), diff.Options{})); !reflect.DeepEqual(got, want) {
		t.Errorf("diff s1 -> imp = %v, want %v", got, want)
	}
	s1, err := inv.RunByName(ctx, "s1")
	if err != nil || s1.Source != inventory.SourceScan {
		t.Errorf("scan run source = %q (%v)", s1.Source, err)
	}

	if _, err := exchange.Apply(ctx, inv, exchange.Batch{Errors: []exchange.RowError{{Row: 1, Reason: "x"}}}, exchange.Options{}); !errors.Is(err, exchange.ErrNothingToImport) {
		t.Errorf("empty batch err = %v", err)
	}
	if count() != 2 {
		t.Errorf("runs = %d, want 2", count())
	}
}

// REQ-EXCHANGE-003 REQ-EXCHANGE-008 AC2: a manual entry goes through the same validation, signature matching and recording as an import.
func TestManualEntrySharesTheImportPath(t *testing.T) {
	ctx := context.Background()
	sigs := shopSignatures(t)
	form := url.Values{"address": {"10.0.0.9"}, "hostnames": {"shop.example"}, "tags": {"crown"},
		"port": {"80", "22", "99999"}, "service": {"http", "ssh", ""}, "scheme": {"http", "", ""}, "title": {"Shop v3.0", "", ""}}

	manual, _ := openInventory(t)
	rep, err := exchange.Apply(ctx, manual, exchange.HostFormFrom(form).Batch(),
		exchange.Options{Source: inventory.SourceManual, Signatures: sigs, ReplaceUserFields: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rep.Errors, []exchange.RowError{{Row: 3, Reason: "port 99999 is out of range 1-65535."}}) {
		t.Errorf("errors = %+v", rep.Errors)
	}
	run, err := manual.RunByName(ctx, rep.Run)
	if err != nil || run.Source != inventory.SourceManual {
		t.Fatalf("manual run = %+v (%v)", run, err)
	}

	imported, _ := openInventory(t)
	apply(t, imported, "csv", []byte("address,hostnames,tags,port,service,scheme,title\n"+
		"10.0.0.9,shop.example,crown,80,http,http,Shop v3.0\n10.0.0.9,,,22,ssh,,\n10.0.0.9,,,99999,,,\n"),
		exchange.Options{Signatures: sigs})

	got, want := comparable(exportOf(t, manual, "")), comparable(exportOf(t, imported, ""))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("manual entry differs from the import\n got %s\nwant %s", exportJSONRaw(inventory.Export{Hosts: got}), exportJSONRaw(inventory.Export{Hosts: want}))
	}
	web := got[0].Services[1]
	if len(web.Findings) != 1 || web.Findings[0].SignatureID != "shop-title" || len(web.Technologies) != 1 || web.Technologies[0].Version != "3.0" {
		t.Fatalf("signature matching did not run: %+v", web)
	}

	edit := url.Values{"address": {"10.0.0.9"}, "tags": {"dmz"}, "notes": {"moved"}, "port": {"80"}, "service": {"http"}}
	if _, err := exchange.Apply(ctx, manual, exchange.HostFormFrom(edit).Batch(),
		exchange.Options{Source: inventory.SourceManual, ReplaceUserFields: true}); err != nil {
		t.Fatal(err)
	}
	h := exportOf(t, manual, "").Hosts[0]
	if !reflect.DeepEqual(h.Tags, []string{"dmz"}) || h.Notes != "moved" || h.Services[0].Status != inventory.StatusUnstable ||
		h.Services[1].Status != inventory.StatusActive || h.Services[1].HTTP != nil {
		t.Fatalf("edited host = %+v", h)
	}
}

// REQ-EXCHANGE-006 AC5: unstable and inactive hosts and services of an export come back in an empty database with
// all their data; their status is re-derived there. Importing the export back into the source re-observes none of them.
func TestJSONRoundTripKeepsEntriesNotActiveInTheExport(t *testing.T) {
	src, _ := openInventory(t)
	scanRun(t, src, "s1", hostWeb("10.0.0.1", "v1", 22, 80), hostWeb("10.0.0.2", "", 22))
	s2, err := src.CreateRun(context.Background(), inventory.RunSpec{Name: "s2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := src.RecordGroup(context.Background(), s2.ID, inventory.GroupResult{Addresses: []string{"10.0.0.2"},
		Hosts: []inventory.HostResult{hostWeb("10.0.0.1", "v1", 22)}}); err != nil {
		t.Fatal(err)
	}
	first := exportOf(t, src, "")
	if h := first.Hosts[1]; h.Status != inventory.StatusUnstable || first.Hosts[0].Services[1].Status != inventory.StatusUnstable {
		t.Fatalf("source export has no unstable entries: %+v", first.Hosts)
	}

	dst, _ := openInventory(t)
	rep := apply(t, dst, "json", exportJSON(t, first), exchange.Options{})
	if rep.Hosts != 2 || rep.Services != 3 || rep.Skipped != 0 {
		t.Fatalf("report = %+v, want 2 hosts, 3 services, 0 skipped", rep)
	}
	got := comparable(exportOf(t, dst, ""))
	want := comparable(first)
	for _, hosts := range [][]inventory.ExportHost{got, want} {
		for i := range hosts {
			hosts[i].Status, hosts[i].MissedRuns, hosts[i].Stability = "", 0, 0
			for j := range hosts[i].Services {
				hosts[i].Services[j].Status, hosts[i].Services[j].MissedRuns, hosts[i].Services[j].Stability = "", 0, 0
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip\n got %s\nwant %s", exportJSONRaw(inventory.Export{Hosts: got}), exportJSONRaw(inventory.Export{Hosts: want}))
	}

	rep = apply(t, src, "json", exportJSON(t, first), exchange.Options{})
	if rep.Skipped != 2 || len(rep.Changes.Changes) != 0 {
		t.Fatalf("re-importing the export into the source: skipped %d, changes %+v; want 2 and none", rep.Skipped, rep.Changes.Changes)
	}
}

// REQ-EXCHANGE-003 AC2: editing a stored host through the form keeps the stored observation it does not show.
func TestManualEditKeepsStoredObservation(t *testing.T) {
	ctx := context.Background()
	inv, _ := openInventory(t)
	scanRun(t, inv, "s1", richHost())
	if err := inv.UpdateHostUserFields(ctx, "172.30.0.12", inventory.HostUserFields{Tags: []string{"dmz"}}); err != nil {
		t.Fatal(err)
	}
	before := exportOf(t, inv, "")
	form := exchange.FormFromHost(before.Hosts[0])
	form.Notes = "moved to the new cluster"
	v := url.Values{"address": {form.Address}, "hostnames": {form.Hostnames}, "tags": {form.Tags}, "notes": {form.Notes}}
	for _, s := range form.Services {
		for k, x := range map[string]string{"port": s.Port, "protocol": s.Protocol, "service": s.Service, "product": s.Product,
			"version": s.Version, "scheme": s.Scheme, "status_code": s.StatusCode, "title": s.Title,
			"technologies": s.Technologies, "findings": s.Findings} {
			v[k] = append(v[k], x)
		}
	}
	rep, err := exchange.Apply(ctx, inv, exchange.HostFormFrom(v).Batch(), exchange.Options{Source: inventory.SourceManual,
		Signatures: shopSignatures(t), ReplaceUserFields: true, KeepStored: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Changes.Changes) != 0 {
		t.Fatalf("notes-only edit changes = %+v, want none", rep.Changes.Changes)
	}
	after := comparable(exportOf(t, inv, ""))
	want := comparable(before)
	want[0].Notes = "moved to the new cluster"
	if !reflect.DeepEqual(after, want) {
		t.Fatalf("edited host\n got %s\nwant %s", exportJSONRaw(inventory.Export{Hosts: after}), exportJSONRaw(inventory.Export{Hosts: want}))
	}
}

// REQ-EXCHANGE-006 AC5: a source with one unstable and one inactive service; both survive an import into an empty
// database as services with their HTTP data, technologies and findings. Only status, missed_runs and stability are
// derived again by the target (accepted by a human decision on T-7z08yrr67g).
func TestJSONRoundTripKeepsUnstableAndInactiveServices(t *testing.T) {
	ctx := context.Background()
	src, _ := openInventory(t)
	web := func(port int, title string) inventory.ServiceResult {
		return inventory.ServiceResult{Port: port, Protocol: "tcp", State: "open", Service: "http", Product: "nginx", Version: "1.27.5",
			HTTP:         &probe.HTTP{Scheme: "http", StatusCode: 200, Title: title, Headers: map[string]string{"server": "nginx/1.27.5"}},
			Technologies: []inventory.Technology{{Name: "nginx", Category: "web-server", Version: "1.27.5", Confidence: 90, Source: "builtin"}},
			Findings:     []inventory.Finding{{SignatureID: "admin-" + title, Kind: "admin-panel", Name: "Admin", Confidence: 80, Evidence: "GET /"}}}
	}
	ssh := inventory.ServiceResult{Port: 22, Protocol: "tcp", State: "open", Service: "ssh", Product: "OpenSSH"}
	seen := [][]inventory.ServiceResult{{ssh, web(80, "eighty"), web(443, "443")}, {ssh, web(443, "443")}, {ssh}}
	for i, svcs := range seen {
		r, err := src.CreateRun(ctx, inventory.RunSpec{Name: fmt.Sprintf("s%d", i+1), InactiveAfter: 2})
		if err != nil {
			t.Fatal(err)
		}
		if err := src.RecordGroup(ctx, r.ID, inventory.GroupResult{Hosts: []inventory.HostResult{{Address: "10.0.0.1", Services: svcs}}}); err != nil {
			t.Fatal(err)
		}
	}
	first := exportOf(t, src, "")
	status := map[int]inventory.Status{}
	for _, s := range first.Hosts[0].Services {
		status[s.Port] = s.Status
	}
	if status[22] != inventory.StatusActive || status[80] != inventory.StatusInactive || status[443] != inventory.StatusUnstable {
		t.Fatalf("source statuses = %v, want 22 active, 80 inactive, 443 unstable", status)
	}

	dst, _ := openInventory(t)
	rep := apply(t, dst, "json", exportJSON(t, first), exchange.Options{})
	if rep.Hosts != 1 || rep.Services != 3 || rep.Skipped != 0 {
		t.Fatalf("report = %+v, want 1 host and 3 services", rep)
	}
	second := exportOf(t, dst, "")
	got, want := comparable(second), comparable(first)
	for _, hosts := range [][]inventory.ExportHost{got, want} {
		for j := range hosts[0].Services {
			s := &hosts[0].Services[j]
			s.Status, s.MissedRuns, s.Stability = "", 0, 0
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip\n got %s\nwant %s", exportJSONRaw(inventory.Export{Hosts: got}), exportJSONRaw(inventory.Export{Hosts: want}))
	}
	for _, s := range second.Hosts[0].Services {
		if s.Status != inventory.StatusActive || s.MissedRuns != 0 || s.Stability != 1 {
			t.Errorf("service %d in the target = %s/%d/%v, want derived active/0/1", s.Port, s.Status, s.MissedRuns, s.Stability)
		}
	}
}

func TestManualEditKeepsTheStoredConfidenceOfAnUnstableHost(t *testing.T) {
	ctx := context.Background()
	inv, _ := openInventory(t)
	host := richHost()
	host.Services[1].Technologies = append(host.Services[1].Technologies, inventory.Technology{Name: "Legacy CRM", Version: "4.2", Confidence: 80, Source: "import"})
	scanRun(t, inv, "s1", host)
	missed, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "s2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.RecordGroup(ctx, missed.ID, inventory.GroupResult{Addresses: []string{"172.30.0.12"}}); err != nil {
		t.Fatal(err)
	}
	if err := inv.SetRunStatus(ctx, missed.ID, inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
	if rep, err := inv.Report(ctx, ""); err != nil || rep.Hosts[0].Stability != 0.5 {
		t.Fatalf("report = %+v, %v; want stability 0.5 before the edit", rep.Hosts, err)
	}
	form := exchange.FormFromHost(exportOf(t, inv, "").Hosts[0])
	v := url.Values{"address": {form.Address}, "hostnames": {form.Hostnames}, "tags": {form.Tags}, "notes": {"edited"}}
	for _, s := range form.Services {
		for k, x := range map[string]string{"port": s.Port, "protocol": s.Protocol, "service": s.Service, "product": s.Product,
			"version": s.Version, "scheme": s.Scheme, "status_code": s.StatusCode, "title": s.Title,
			"technologies": s.Technologies, "findings": s.Findings} {
			v[k] = append(v[k], x)
		}
	}
	if _, err := exchange.Apply(ctx, inv, exchange.HostFormFrom(v).Batch(), exchange.Options{Source: inventory.SourceManual,
		Signatures: shopSignatures(t), ReplaceUserFields: true, KeepStored: true}); err != nil {
		t.Fatal(err)
	}
	d, err := inv.HostDetail(ctx, "172.30.0.12")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d.Host.Services {
		for _, tech := range s.Technologies {
			if want := map[string]int{"Shop": 70, "nginx": 90, "Legacy CRM": 80}[tech.Name]; tech.Confidence != want {
				t.Errorf("stored confidence of %s after the edit = %d, want the detected %d", tech.Name, tech.Confidence, want)
			}
		}
	}
}

func rawConfidences(t *testing.T, exp inventory.Export) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, h := range exp.Hosts {
		for _, s := range h.Services {
			for _, tech := range s.Technologies {
				if tech.ConfidenceRaw == nil {
					t.Fatalf("%s has no confidence_raw in the report", tech.Name)
				}
				out[tech.Name] = *tech.ConfidenceRaw
			}
		}
	}
	return out
}

func TestReportRoundTripKeepsTheRawConfidenceOfAnUnstableHost(t *testing.T) {
	ctx := context.Background()
	src, _ := openInventory(t)
	host := richHost()
	host.Services[1].Technologies = append(host.Services[1].Technologies, inventory.Technology{Name: "Legacy CRM", Version: "4.2", Confidence: 80, Source: "import"})
	scanRun(t, src, "s1", host)
	missed, err := src.CreateRun(ctx, inventory.RunSpec{Name: "s2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := src.RecordGroup(ctx, missed.ID, inventory.GroupResult{Addresses: []string{"172.30.0.12"}}); err != nil {
		t.Fatal(err)
	}
	if err := src.SetRunStatus(ctx, missed.ID, inventory.RunCompleted); err != nil {
		t.Fatal(err)
	}
	first, err := src.Report(ctx, "")
	if err != nil || first.Hosts[0].Stability != 0.5 {
		t.Fatalf("report = %+v, %v; want stability 0.5", first.Hosts, err)
	}
	data := exportJSON(t, first)
	if !bytes.Contains(data, []byte(`"confidence":40,"confidence_raw":80`)) {
		t.Fatalf("export lacks reported 40 and raw 80 for Legacy CRM: %s", data)
	}

	dst, _ := openInventory(t)
	apply(t, dst, "json", data, exchange.Options{})
	second, err := dst.Report(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rawConfidences(t, second), rawConfidences(t, first); !reflect.DeepEqual(got, want) {
		t.Fatalf("confidence_raw after export -> import -> export = %v, want %v", got, want)
	}
}

func TestImportWithoutConfidenceRawStoresTheGivenConfidence(t *testing.T) {
	b, err := exchange.Parse("json", []byte(`{"schema":"`+inventory.ExportSchema+`","hosts":[{"address":"172.30.0.20","services":[
		{"port":80,"protocol":"tcp","technologies":[{"name":"A","confidence":40},{"name":"B","confidence":40,"confidence_raw":80}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	techs := b.Entries[0].Host.Services[0].Technologies
	if techs[0].Confidence != 40 || techs[1].Confidence != 80 || techs[0].ConfidenceRaw != nil || techs[1].ConfidenceRaw != nil {
		t.Fatalf("parsed technologies = %+v, want A 40 and B 80 stored as raw", techs)
	}
}
