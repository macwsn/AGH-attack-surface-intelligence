package defectdojo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
)

type memStore struct {
	s     Settings
	audit []string
}

func (m *memStore) Load(context.Context) (Settings, error) { return m.s, nil }

func (m *memStore) Save(_ context.Context, s Settings) error {
	m.s = s
	return nil
}

func (m *memStore) Audit(_ context.Context, a auth.Actor, action, target string) error {
	m.audit = append(m.audit, a.Username+" "+action+" "+target)
	return nil
}

type fakeExporter struct{ runs map[string]inventory.Export }

func (f fakeExporter) Export(_ context.Context, run string) (inventory.Export, error) {
	e, ok := f.runs[run]
	if !ok {
		return inventory.Export{}, inventory.ErrUnknownRun
	}
	return e, nil
}

var actor = auth.Actor{Username: "olga", Addr: "127.0.0.1"}

func newService(t *testing.T) (*Service, *memStore, *fakeDojo) {
	t.Helper()
	f, srv := newFakeDojo(t)
	m := &memStore{}
	exp := sampleExport(time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), "e")
	svc := &Service{Store: m, Inventory: fakeExporter{runs: map[string]inventory.Export{"r2": exp}}, HTTP: srv.Client()}
	if err := svc.Configure(context.Background(), actor, Config{BaseURL: srv.URL + "/", Token: testToken, ProductID: 2, EngagementID: 3}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if c := f.calls(); len(c) != 1 || c[0].Path != "/api/v2/engagements/3/" {
		t.Fatalf("Configure did not run the connection test: %+v", c)
	}
	f.mu.Lock()
	f.requests = nil
	f.mu.Unlock()
	return svc, m, f
}

// REQ-DEFECTDOJO-001
func TestConfigureKeepsTokenHidden(t *testing.T) {
	svc, m, _ := newService(t)
	ctx := context.Background()
	v, err := svc.View(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.TokenSet || v.ProductID != 2 || v.EngagementID != 3 || strings.HasSuffix(v.BaseURL, "/") {
		t.Fatalf("view = %+v", v)
	}
	base := m.s.BaseURL
	if err := svc.Configure(ctx, actor, Config{BaseURL: base, ProductID: 2, EngagementID: 3}); err != nil {
		t.Fatalf("Configure without token: %v", err)
	}
	if m.s.Token != testToken {
		t.Fatal("an empty token field replaced the stored token")
	}
	if err := svc.Configure(ctx, actor, Config{BaseURL: base, Token: "new-token", ProductID: 2, EngagementID: 3}); err != nil || m.s.Token != "new-token" {
		t.Fatalf("token not replaced: %v", err)
	}
	if want := "olga defectdojo.configure " + base; len(m.audit) != 3 || m.audit[0] != want {
		t.Fatalf("audit = %v", m.audit)
	}
	for _, c := range []Config{
		{BaseURL: "not a url", ProductID: 2, EngagementID: 3},
		{BaseURL: base, ProductID: 0, EngagementID: 3},
		{BaseURL: base, ProductID: 2, EngagementID: -1},
	} {
		if err := svc.Configure(ctx, actor, c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Configure(%+v) = %v", c, err)
		}
	}
	empty := &Service{Store: &memStore{}}
	if err := empty.Configure(ctx, actor, Config{BaseURL: base, ProductID: 2, EngagementID: 3}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("first Configure without token = %v", err)
	}
}

// REQ-DEFECTDOJO-002
func TestTestConnection(t *testing.T) {
	svc, m, f := newService(t)
	if err := svc.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if c := f.calls(); len(c) != 1 || c[0].Path != "/api/v2/engagements/3/" || c[0].Auth != "Token "+testToken {
		t.Fatalf("calls = %+v", c)
	}
	f.status, f.body = 403, `{"detail":"no"}`
	err := svc.TestConnection(context.Background())
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("TestConnection on 403 = %v", err)
	}
	m.s = Settings{}
	if err := svc.TestConnection(context.Background()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("unconfigured = %v", err)
	}
}

// REQ-DEFECTDOJO-003 REQ-DEFECTDOJO-004
func TestExportImportsThenReimports(t *testing.T) {
	svc, m, f := newService(t)
	ctx := context.Background()
	res, err := svc.Export(ctx, actor, "r2")
	if err != nil {
		t.Fatalf("first Export: %v", err)
	}
	if res.Run != "r2" || res.Hosts != 2 || res.Services != 3 || res.Findings != 7 || res.NmapTestID != 41 || res.FindingsTestID != 42 {
		t.Fatalf("first result = %+v", res)
	}
	if m.s.NmapTestID != 41 || m.s.FindingsTestID != 42 {
		t.Fatalf("test ids not kept: %+v", m.s)
	}
	nmapXML, _, _ := NmapXML(sampleExport(time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), "e"))
	findings, _, _ := GenericFindings(sampleExport(time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), "e"))
	calls := f.calls()
	if len(calls) != 2 {
		t.Fatalf("%d calls", len(calls))
	}
	checkUpload(t, calls[0], ImportPath, map[string]string{"scan_type": ScanTypeNmap, "engagement": "3"}, NmapFile, string(nmapXML))
	checkUpload(t, calls[1], ImportPath, map[string]string{"scan_type": ScanTypeGeneric, "engagement": "3"}, FindingsFile, string(findings))

	res, err = svc.Export(ctx, actor, "r2")
	if err != nil {
		t.Fatalf("second Export: %v", err)
	}
	if res.NmapTestID != 41 || res.FindingsTestID != 42 || res.NmapPath != ReimportPath {
		t.Fatalf("second result = %+v", res)
	}
	calls = f.calls()[2:]
	checkUpload(t, calls[0], ReimportPath, map[string]string{"scan_type": ScanTypeNmap, "test": "41"}, NmapFile, string(nmapXML))
	checkUpload(t, calls[1], ReimportPath, map[string]string{"scan_type": ScanTypeGeneric, "test": "42"}, FindingsFile, string(findings))
	if m.audit[len(m.audit)-1] != "olga defectdojo.export r2" {
		t.Fatalf("audit = %v", m.audit)
	}

	if err := svc.Configure(ctx, actor, Config{BaseURL: m.s.BaseURL, ProductID: 2, EngagementID: 4}); err != nil {
		t.Fatal(err)
	}
	if m.s.NmapTestID != 0 || m.s.FindingsTestID != 0 {
		t.Fatalf("new engagement kept old test ids: %+v", m.s)
	}
}

// REQ-DEFECTDOJO-005
func TestExportFailureKeepsStateAndHidesToken(t *testing.T) {
	svc, m, f := newService(t)
	f.status, f.body = 500, "boom "+testToken
	_, err := svc.Export(context.Background(), actor, "r2")
	if err == nil || !strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("Export on 500 = %v", err)
	}
	if m.s.NmapTestID != 0 {
		t.Fatalf("failed import stored a test id: %+v", m.s)
	}
	if _, err := svc.Export(context.Background(), actor, "nope"); !errors.Is(err, inventory.ErrUnknownRun) {
		t.Fatalf("unknown run = %v", err)
	}
}

// REQ-DEFECTDOJO-006
func TestDryRunWritesPayloadsWithoutHTTP(t *testing.T) {
	svc, m, f := newService(t)
	m.s.NmapTestID = 41
	dir := filepath.Join(t.TempDir(), "out")
	res, err := svc.DryRun(context.Background(), "r2", dir)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if res.NmapPath != ReimportPath || res.FindingsPath != ImportPath || res.Findings != 7 {
		t.Fatalf("result = %+v", res)
	}
	if c := f.calls(); len(c) != 0 {
		t.Fatalf("dry run made %d requests", len(c))
	}
	for _, name := range []string{NmapFile, FindingsFile} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || len(b) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	unconfigured := &Service{Store: &memStore{}, Inventory: svc.Inventory}
	if _, err := unconfigured.DryRun(context.Background(), "r2", dir); err != nil {
		t.Fatalf("dry run without configuration: %v", err)
	}
}

// REQ-DEFECTDOJO-001
func TestConfigureNewBaseURLNeedsNewToken(t *testing.T) {
	svc, m, f := newService(t)
	ctx := context.Background()
	m.s.NmapTestID, m.s.FindingsTestID = 41, 42
	if err := svc.Configure(ctx, actor, Config{BaseURL: m.s.BaseURL, ProductID: 2, EngagementID: 3}); err != nil {
		t.Fatalf("same target without token: %v", err)
	}
	if m.s.NmapTestID != 41 || m.s.FindingsTestID != 42 || m.s.Token != testToken {
		t.Fatalf("same target lost state: %+v", m.s)
	}
	other, otherSrv := newFakeDojo(t)
	err := svc.Configure(ctx, actor, Config{BaseURL: otherSrv.URL, ProductID: 2, EngagementID: 3})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "base URL changes") {
		t.Fatalf("new base URL without token = %v", err)
	}
	if strings.HasPrefix(m.s.BaseURL, otherSrv.URL) || m.s.Token != testToken {
		t.Fatalf("settings changed: %+v", m.s)
	}
	_ = svc.TestConnection(ctx)
	if c := other.calls(); len(c) != 0 {
		t.Fatalf("the saved token was sent to the new host: %+v", c)
	}
	if c := f.calls(); len(c) != 1 || c[0].Auth != "Token "+testToken {
		t.Fatalf("test connection did not go to the saved host: %+v", c)
	}
	if err := svc.Configure(ctx, actor, Config{BaseURL: otherSrv.URL, Token: "other-token", ProductID: 2, EngagementID: 3}); err != nil {
		t.Fatalf("new base URL with token: %v", err)
	}
	if m.s.Token != "other-token" || m.s.NmapTestID != 0 {
		t.Fatalf("after move: %+v", m.s)
	}
}

// REQ-DEFECTDOJO-003
func TestExportKeepsNmapTestIDWhenFindingsFail(t *testing.T) {
	svc, m, f := newService(t)
	client := svc.HTTP
	calls := 0
	svc.HTTP = doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		f.mu.Lock()
		f.status = 0
		if calls == 2 {
			f.status = 500
		}
		f.mu.Unlock()
		return client.Do(req)
	})
	if _, err := svc.Export(context.Background(), actor, "r2"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("Export = %v", err)
	}
	if m.s.NmapTestID != 41 || m.s.FindingsTestID != 0 {
		t.Fatalf("state after partial failure = %+v", m.s)
	}
	if _, err := svc.Export(context.Background(), actor, "r2"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	c := f.calls()[2:]
	if c[0].Path != ReimportPath || c[0].Fields["test"] != "41" || c[1].Path != ImportPath || m.s.FindingsTestID != 42 {
		t.Fatalf("retry calls = %+v, state %+v", c, m.s)
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

// REQ-DEFECTDOJO-009
func TestExportRefusesOlderRunUnlessForced(t *testing.T) {
	svc, m, f := newService(t)
	ctx := context.Background()
	older := sampleExport(time.Time{}, "e")
	older.Run, older.RunStartedAt = "r1", time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	newer := sampleExport(time.Time{}, "e")
	newer.RunStartedAt = older.RunStartedAt.Add(time.Hour)
	svc.Inventory = fakeExporter{runs: map[string]inventory.Export{"r1": older, "r2": newer}}
	if _, err := svc.Export(ctx, actor, "r2"); err != nil {
		t.Fatalf("Export r2: %v", err)
	}
	if m.s.LastRun != "r2" || !m.s.LastRunStartedAt.Equal(newer.RunStartedAt) {
		t.Fatalf("last exported run not kept: %+v", m.s)
	}
	before := len(f.calls())
	_, err := svc.Export(ctx, actor, "r1")
	if !errors.Is(err, ErrOlderRun) || !strings.Contains(err.Error(), "run r1 is older than run r2") || len(f.calls()) != before {
		t.Fatalf("older export = %v, %d requests", err, len(f.calls())-before)
	}
	if _, err := svc.Export(ctx, actor, "r2"); err != nil {
		t.Fatalf("re-export of the last run: %v", err)
	}
	res, err := svc.ForceExport(ctx, actor, "r1")
	if err != nil || res.Run != "r1" || m.s.LastRun != "r1" {
		t.Fatalf("forced export = %+v, %v, state %+v", res, err, m.s)
	}
	body, _, _ := NmapXML(older)
	start := fmt.Sprintf(`start="%d"`, older.RunStartedAt.Unix())
	if c := f.calls(); !strings.Contains(c[len(c)-2].File, start) || !strings.Contains(string(body), "<nmaprun") {
		t.Fatalf("nmap start is not the run's start:\n%s", c[len(c)-2].File)
	}
}

// REQ-DEFECTDOJO-001 REQ-DEFECTDOJO-007
func TestConfigureForceAndTargets(t *testing.T) {
	svc, m, f := newService(t)
	ctx := context.Background()
	f.status, f.body = http.StatusNotFound, `{"detail": "Not found."}`
	err := svc.Configure(ctx, actor, Config{BaseURL: m.s.BaseURL, ProductID: 2, EngagementID: 7})
	if !errors.Is(err, ErrNotSaved) || !strings.Contains(err.Error(), "Not found.") || m.s.EngagementID != 3 {
		t.Fatalf("failing configure = %v, state %+v", err, m.s)
	}
	before := len(f.calls())
	if err := svc.Configure(ctx, actor, Config{BaseURL: m.s.BaseURL, ProductID: 2, EngagementID: 7, Force: true}); err != nil || m.s.EngagementID != 7 {
		t.Fatalf("forced configure = %v, state %+v", err, m.s)
	}
	if len(f.calls()) != before {
		t.Fatal("forced configure ran the connection test")
	}
	m.s.NmapTestID = 70
	f.status = 0
	firstBase := m.s.BaseURL
	other, otherSrv := newFakeDojo(t)
	svc.HTTP = otherSrv.Client()
	if err := svc.Configure(ctx, actor, Config{BaseURL: otherSrv.URL, Token: "other", ProductID: 2, EngagementID: 7}); err != nil || m.s.NmapTestID != 0 {
		t.Fatalf("other host = %v, state %+v", err, m.s)
	}
	if len(other.calls()) != 1 {
		t.Fatalf("connection test calls on the new host: %+v", other.calls())
	}
	first := m.s
	if err := svc.Configure(ctx, actor, Config{BaseURL: firstBase, Token: testToken, ProductID: 2, EngagementID: 7}); err != nil {
		t.Fatalf("back to the first host: %v", err)
	}
	if m.s.NmapTestID != 70 || m.s.Targets == nil || (*m.s.Targets)[first.target()].NmapTestID != 0 {
		t.Fatalf("test ids not remembered per target: %+v", m.s)
	}
}
