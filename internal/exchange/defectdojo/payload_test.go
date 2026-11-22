package defectdojo

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"slices"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/scan/nmap"
)

var allKinds = []string{"admin-panel", "staging", "iot", "interesting-header", "interesting-cookie", "custom", "technology"}

func sampleExport(generated time.Time, evidence string) inventory.Export {
	seen := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	var findings []inventory.Finding
	for _, k := range allKinds {
		findings = append(findings, inventory.Finding{SignatureID: "sig-" + k, Kind: k, Name: "Sig " + k, Confidence: 80, Evidence: evidence})
	}
	return inventory.Export{
		Schema: inventory.ExportSchema, GeneratedAt: generated, Run: "r2", RunStartedAt: generated,
		Hosts: []inventory.ExportHost{
			{Address: "192.0.2.10", Hostnames: []string{"admin.example"}, Status: inventory.StatusActive, Services: []inventory.ExportService{
				{Port: 443, Protocol: "tcp", State: "open", Status: inventory.StatusActive, Service: "http", Product: "nginx", Version: "1.27.5",
					LastSeen: seen, HTTP: &probe.HTTP{Scheme: "https"}, Findings: findings},
				{Port: 8080, Protocol: "tcp", State: "open", Status: inventory.StatusUnstable, Service: "http",
					Findings: []inventory.Finding{{SignatureID: "gone", Kind: "admin-panel"}}},
				{Port: 22, Protocol: "tcp", State: "open", Status: inventory.StatusActive, Service: "ssh", Product: "OpenSSH", LastSeen: seen},
			}},
			{Address: "192.0.2.11", Status: inventory.StatusActive, Services: []inventory.ExportService{
				{Port: 80, Protocol: "tcp", State: "open", Status: inventory.StatusActive, Service: "http", LastSeen: seen,
					HTTP: &probe.HTTP{Scheme: "http"}, Findings: []inventory.Finding{{SignatureID: "sig-admin-panel", Kind: "admin-panel", Name: "Sig admin-panel"}}},
			}},
			{Address: "192.0.2.12", Status: inventory.StatusInactive, Services: []inventory.ExportService{
				{Port: 80, Protocol: "tcp", State: "open", Status: inventory.StatusInactive, Service: "http",
					Findings: []inventory.Finding{{SignatureID: "old", Kind: "staging"}}},
			}},
		},
	}
}

// REQ-DEFECTDOJO-003
func TestNmapXMLIsNmapCompatible(t *testing.T) {
	gen := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	body, services, err := NmapXML(sampleExport(gen, "x"))
	if err != nil {
		t.Fatalf("NmapXML: %v", err)
	}
	if services != 3 {
		t.Fatalf("services = %d, want 3", services)
	}
	if !bytes.HasPrefix(body, []byte(xml.Header)) {
		t.Fatalf("no xml header:\n%s", body)
	}
	var root struct {
		XMLName xml.Name
		Scanner string `xml:"scanner,attr"`
		Start   int64  `xml:"start,attr"`
	}
	if err := xml.Unmarshal(body, &root); err != nil {
		t.Fatal(err)
	}
	if root.XMLName.Local != "nmaprun" || root.Scanner != "nmap" || root.Start != gen.Unix() {
		t.Fatalf("root = %+v", root)
	}
	hosts, err := nmap.Parse(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("nmap.Parse: %v", err)
	}
	want := []nmap.Host{
		{Address: "192.0.2.10", Hostnames: []string{"admin.example"}, Up: true, Ports: []nmap.Port{
			{Number: 443, Protocol: "tcp", State: "open", Service: "http", Product: "nginx", Version: "1.27.5", Tunnel: "ssl"},
			{Number: 22, Protocol: "tcp", State: "open", Service: "ssh", Product: "OpenSSH"},
		}},
		{Address: "192.0.2.11", Up: true, Ports: []nmap.Port{{Number: 80, Protocol: "tcp", State: "open", Service: "http"}}},
	}
	if len(hosts) != len(want) {
		t.Fatalf("hosts = %+v", hosts)
	}
	for i := range want {
		if hosts[i].Address != want[i].Address || !slices.Equal(hosts[i].Hostnames, want[i].Hostnames) || !hosts[i].Up || !slices.Equal(hosts[i].Ports, want[i].Ports) {
			t.Fatalf("host %d = %+v, want %+v", i, hosts[i], want[i])
		}
	}
}

func decodeFindings(t *testing.T, body []byte) []genericFinding {
	t.Helper()
	var r genericReport
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	return r.Findings
}

// REQ-DEFECTDOJO-004
func TestGenericFindingsInfoWithEndpointAndStableID(t *testing.T) {
	body, n, err := GenericFindings(sampleExport(time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), "first"))
	if err != nil {
		t.Fatalf("GenericFindings: %v", err)
	}
	got := decodeFindings(t, body)
	if n != 7 || len(got) != 10 {
		t.Fatalf("findings = %d (%d), want 7 and 3 open services: %s", n, len(got), body)
	}
	var kinds, ids []string
	for _, f := range got {
		if f.Severity != "Info" {
			t.Fatalf("%s severity %q", f.Title, f.Severity)
		}
		if len(f.Endpoints) != 1 || f.Endpoints[0].Host == "" || f.Endpoints[0].Port == 0 {
			t.Fatalf("%s endpoints %+v", f.Title, f.Endpoints)
		}
		if f.Title == "" || f.Description == "" || f.Date != "2026-11-20" {
			t.Fatalf("finding %+v", f)
		}
		kinds = append(kinds, f.VulnIDFromTool)
		ids = append(ids, f.UniqueIDFromTool)
	}
	for _, k := range allKinds[:6] {
		if !slices.Contains(kinds, "sig-"+k) {
			t.Errorf("kind %s not exported", k)
		}
	}
	if slices.Contains(kinds, "sig-technology") || slices.Contains(kinds, "gone") || slices.Contains(kinds, "old") {
		t.Fatalf("exported technology, unstable or inactive findings: %v", kinds)
	}
	first := got[0]
	if first.Endpoints[0] != (genericEndpoint{Protocol: "https", Host: "192.0.2.10", Port: 443}) ||
		first.UniqueIDFromTool != "asi:192.0.2.10:tcp/443:sig-admin-panel" {
		t.Fatalf("first finding = %+v", first)
	}
	last := got[6]
	if last.Endpoints[0] != (genericEndpoint{Protocol: "http", Host: "192.0.2.11", Port: 80}) ||
		last.UniqueIDFromTool != "asi:192.0.2.11:tcp/80:sig-admin-panel" {
		t.Fatalf("last finding = %+v", last)
	}
	sorted := slices.Clone(ids)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(ids) {
		t.Fatalf("unique ids repeat: %v", ids)
	}

	again, _, err := GenericFindings(sampleExport(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), "second"))
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range decodeFindings(t, again) {
		if f.UniqueIDFromTool != got[i].UniqueIDFromTool || f.Title != got[i].Title || strings.ReplaceAll(f.Description, "second", "first") != got[i].Description {
			t.Fatalf("re-export changed identity of finding %d: %+v vs %+v", i, f, got[i])
		}
	}
}

func TestGenericFindingsEmpty(t *testing.T) {
	body, n, err := GenericFindings(inventory.Export{Run: "r"})
	if err != nil || n != 0 || string(body) != "{\n  \"findings\": []\n}\n" {
		t.Fatalf("empty = %q %d %v", body, n, err)
	}
}

// REQ-DEFECTDOJO-011 REQ-SIGNATURES-027: two admin-panel findings of one service with different names are sent once.
func TestGenericFindingsMergesAdminPanelsWithDifferentNames(t *testing.T) {
	exp := inventory.Export{Run: "r", Hosts: []inventory.ExportHost{{Address: "192.0.2.12", Status: inventory.StatusActive, Services: []inventory.ExportService{{
		Port: 80, Protocol: "tcp", State: "open", Status: inventory.StatusActive, Service: "http", HTTP: &probe.HTTP{Scheme: "http"},
		Findings: []inventory.Finding{
			{SignatureID: "admin-panel-login", Kind: "admin-panel", Name: "Admin panel login form", Confidence: 80},
			{SignatureID: "builtin-admin-login", Kind: "admin-panel", Name: "Admin login page", Confidence: 70},
		},
	}}}}}
	body, n, err := GenericFindings(exp)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || !strings.Contains(string(body), "builtin-admin-login") || !strings.Contains(string(body), `"vuln_id_from_tool": "admin-panel-login"`) {
		t.Errorf("findings = %d, want one admin panel from admin-panel-login naming builtin-admin-login:\n%s", n, body)
	}
}
