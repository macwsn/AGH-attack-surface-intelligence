package defectdojo

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"asi/internal/inventory"
)

type tickingExporter struct {
	mu   sync.Mutex
	now  time.Time
	runs map[string]inventory.Export
}

func (e *tickingExporter) Export(_ context.Context, run string) (inventory.Export, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	exp, ok := e.runs[run]
	if !ok {
		return inventory.Export{}, inventory.ErrUnknownRun
	}
	e.now = e.now.Add(time.Minute)
	exp.GeneratedAt = e.now
	return exp, nil
}

// AC1: save engagement 999, save the original engagement again, export: the earlier tests are reimported.
func TestDojoFixEngagementRoundTripReusesTests(t *testing.T) {
	svc, m, f := newService(t)
	ctx := context.Background()
	if _, err := svc.Export(ctx, actor, "r2"); err != nil {
		t.Fatalf("first Export: %v", err)
	}
	if m.s.NmapTestID != 41 || m.s.FindingsTestID != 42 {
		t.Fatalf("first export state %+v", m.s)
	}
	if err := svc.Configure(ctx, actor, Config{BaseURL: m.s.BaseURL, ProductID: 2, EngagementID: 999}); err != nil {
		t.Fatalf("Configure engagement 999: %v", err)
	}
	if err := svc.Configure(ctx, actor, Config{BaseURL: m.s.BaseURL, ProductID: 2, EngagementID: 3}); err != nil {
		t.Fatalf("Configure engagement 3: %v", err)
	}
	before := len(f.calls())
	res, err := svc.Export(ctx, actor, "r2")
	if err != nil {
		t.Fatalf("Export after engagement round trip: %v", err)
	}
	var paths []string
	for _, c := range f.calls()[before:] {
		if c.Method == http.MethodPost {
			paths = append(paths, c.Path+"?test="+c.Fields["test"])
		}
	}
	want := []string{ReimportPath + "?test=41", ReimportPath + "?test=42"}
	if strings.Join(paths, " ") != strings.Join(want, " ") || res.NmapTestID != 41 || res.FindingsTestID != 42 {
		t.Fatalf("engagement round trip created new tests: uploads %v, want %v; result %+v", paths, want, res)
	}
}

// AC2: a stored test that DefectDojo no longer has is recreated with import-scan once.
func TestDojoFixMissingTestIsRecreated(t *testing.T) {
	svc, m, f := newService(t)
	ctx := context.Background()
	m.s.NmapTestID, m.s.FindingsTestID = 41, 42
	f.nextTest = 50
	client := svc.HTTP
	svc.HTTP = doerFunc(func(req *http.Request) (*http.Response, error) {
		f.mu.Lock()
		f.status, f.body = 0, ""
		if req.URL.Path == ReimportPath {
			f.status, f.body = http.StatusBadRequest, `{"test": ["Invalid pk \"41\" - object does not exist."]}`
		}
		f.mu.Unlock()
		return client.Do(req)
	})
	res, err := svc.Export(ctx, actor, "r2")
	if err != nil {
		t.Fatalf("Export with a deleted test: %v", err)
	}
	var imports int
	for _, c := range f.calls() {
		if c.Path == ImportPath {
			imports++
			if c.Fields["engagement"] != "3" {
				t.Fatalf("import into engagement %q", c.Fields["engagement"])
			}
		}
	}
	if imports != 2 || res.NmapTestID == 41 || res.FindingsTestID == 42 || m.s.NmapTestID != res.NmapTestID || m.s.FindingsTestID != res.FindingsTestID {
		t.Fatalf("deleted tests not recreated once: %d imports, result %+v, state %+v", imports, res, m.s)
	}
}

// AC4: errors carry DefectDojo's answer, a rejected token and a non-DefectDojo base URL are named.
func TestDojoFixErrorsCarryTheCause(t *testing.T) {
	f, srv := newFakeDojo(t)
	c := testClient(srv)
	ctx := context.Background()
	up := Upload{ScanType: ScanTypeNmap, FileName: NmapFile, File: []byte("<nmaprun/>")}

	f.status, f.body = http.StatusBadRequest, `{"engagement": ["Engagement is closed"], "echo": "`+testToken+`"}`
	_, err := c.Import(ctx, 3, up)
	if err == nil || !strings.Contains(err.Error(), "Engagement is closed") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("400 error does not carry the response body (or leaks the token): %v", err)
	}

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		f.status, f.body = status, `{"detail": "Invalid token."}`
		err := c.CheckEngagement(ctx, 2, 3)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "token was rejected") {
			t.Fatalf("%d error does not say the token was rejected: %v", status, err)
		}
	}

	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!DOCTYPE html><html><body>Login</body></html>")
	}))
	t.Cleanup(html.Close)
	err = (&Client{BaseURL: html.URL, Token: testToken, HTTP: html.Client()}).CheckEngagement(ctx, 2, 3)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "does not look like a defectdojo api") {
		t.Fatalf("non-JSON answer does not say the base URL is not a DefectDojo API: %v", err)
	}
}

// AC4: configure runs the connection test and refuses to save a configuration that fails it.
func TestDojoFixConfigureRefusesFailingConnection(t *testing.T) {
	f, srv := newFakeDojo(t)
	m := &memStore{}
	svc := &Service{Store: m, HTTP: srv.Client()}
	f.status, f.body = http.StatusForbidden, `{"detail": "Invalid token."}`
	err := svc.Configure(context.Background(), actor, Config{BaseURL: srv.URL, Token: testToken, ProductID: 2, EngagementID: 3})
	if err == nil || m.s.BaseURL != "" {
		t.Fatalf("configure saved a configuration whose connection test fails: err %v, stored %+v", err, m.s)
	}
	if len(f.calls()) == 0 {
		t.Fatal("configure did not run the connection test")
	}
}

// AC5: one Info finding per open service with a stable id; outdated findings are Low with versions; evidence in the description.
func TestDojoFixServiceAndOutdatedFindings(t *testing.T) {
	exp := sampleExport(time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), "evidence-text-xyz")
	svc := &exp.Hosts[1].Services[0]
	svc.Product, svc.Version = "nginx", "1.18.0"
	svc.Findings = append(svc.Findings, inventory.Finding{SignatureID: "outdated-nginx", Kind: "outdated", Name: "Outdated nginx",
		Version: "1.18.0", Confidence: 90, Evidence: "nginx 1.18.0 is older than the minimum supported version 1.26.0 (support table checked 2026-10-01)"})
	body, _, err := GenericFindings(exp)
	if err != nil {
		t.Fatalf("GenericFindings: %v", err)
	}
	got := decodeFindings(t, body)
	var service, outdated *genericFinding
	services := 0
	for i := range got {
		f := &got[i]
		if strings.HasPrefix(f.Title, "Open service: ") {
			services++
		}
		if f.Title == "Open service: 192.0.2.10:443 nginx 1.27.5" {
			service = f
		}
		if f.VulnIDFromTool == "outdated-nginx" {
			outdated = f
		}
		if f.VulnIDFromTool == "sig-admin-panel" && f.Endpoints[0].Port == 443 && !strings.Contains(f.Description, "evidence-text-xyz") {
			t.Errorf("evidence is not in the description: %q", f.Description)
		}
	}
	if service == nil || services != 3 || service.Severity != "Info" || service.UniqueIDFromTool == "" {
		t.Fatalf("services are not exported as Info findings (one per host:port): %d service findings, 443 = %+v", services, service)
	}
	if outdated == nil || outdated.Severity != "Low" || !strings.Contains(outdated.Description, "1.18.0") || !strings.Contains(outdated.Description, "1.26.0") {
		t.Fatalf("outdated finding not exported as Low with detected and minimum versions: %+v", outdated)
	}
	again, _, err := GenericFindings(exp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(again), `"unique_id_from_tool": "`+service.UniqueIDFromTool+`"`) {
		t.Fatalf("service finding id is not stable: %s", service.UniqueIDFromTool)
	}
}

// AC6: the dry-run payloads are byte-identical to what export sends.
func TestDojoFixDryRunMatchesSentPayloads(t *testing.T) {
	svc, _, f := newService(t)
	svc.Inventory = &tickingExporter{now: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC),
		runs: map[string]inventory.Export{"r2": sampleExport(time.Time{}, "e")}}
	dir := t.TempDir()
	if _, err := svc.DryRun(context.Background(), "r2", dir); err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if _, err := svc.Export(context.Background(), actor, "r2"); err != nil {
		t.Fatalf("Export: %v", err)
	}
	sent := map[string]string{}
	for _, c := range f.calls() {
		if c.Method == http.MethodPost {
			sent[c.FileName] = c.File
		}
	}
	for _, name := range []string{NmapFile, FindingsFile} {
		dry, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(dry) != sent[name] {
			t.Fatalf("dry-run %s differs from the sent payload:\ndry:\n%s\nsent:\n%s", name, dry, sent[name])
		}
	}
}
