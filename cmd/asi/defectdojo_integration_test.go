//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"asi/internal/exchange/defectdojo"
	"asi/internal/scan/scantest"
)

const dojoToken = "cli-dojo-token-123"

type dojoCall struct {
	method, path, auth string
	fields             map[string]string
	file               []byte
}

type dojoServer struct {
	mu     sync.Mutex
	calls  []dojoCall
	nextID int
	status int
}

func (d *dojoServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call := dojoCall{method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization"), fields: map[string]string{}}
	if r.Method == http.MethodPost {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for k, v := range r.MultipartForm.Value {
			call.fields[k] = v[0]
		}
		if fh := r.MultipartForm.File["file"]; len(fh) == 1 {
			f, _ := fh[0].Open()
			call.file, _ = io.ReadAll(f)
			f.Close()
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, call)
	if d.status != 0 {
		w.WriteHeader(d.status)
		fmt.Fprintf(w, `{"detail": "bad token %s"}`, call.auth)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/engagements/5/":
		fmt.Fprint(w, `{"id": 5, "product": 4}`)
	case r.URL.Path == defectdojo.ImportPath:
		d.nextID++
		fmt.Fprintf(w, `{"test_id": %d}`, 100+d.nextID)
	case r.URL.Path == defectdojo.ReimportPath:
		fmt.Fprintf(w, `{"test_id": %s}`, call.fields["test"])
	default:
		http.NotFound(w, r)
	}
}

func (d *dojoServer) take() []dojoCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.calls
	d.calls = nil
	return out
}

func (c *cliEnv) runDojo(srv *httptest.Server, stdin string, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	tr := &scantest.Transport{Handler: http.HandlerFunc(c.net.handler)}
	deps := scanDeps{runner: c.net.runner(), transport: tr.For, dojo: srv.Client()}
	code := runWith(context.Background(), deps, args, strings.NewReader(stdin), &stdout, &stderr, func(k string) string { return c.env[k] })
	return code, stdout.String(), stderr.String()
}

func uniqueIDs(t *testing.T, body []byte) []string {
	t.Helper()
	var r struct {
		Findings []struct {
			Severity  string `json:"severity"`
			UniqueID  string `json:"unique_id_from_tool"`
			VulnID    string `json:"vuln_id_from_tool"`
			Endpoints []struct {
				Host string `json:"host"`
			} `json:"endpoints"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("findings json: %v\n%s", err, body)
	}
	var ids []string
	for _, f := range r.Findings {
		if f.VulnID == "open-service" {
			continue
		}
		if f.Severity != "Info" || len(f.Endpoints) != 1 || f.Endpoints[0].Host != "192.0.2.1" {
			t.Fatalf("finding %+v", f)
		}
		ids = append(ids, f.UniqueID)
	}
	return ids
}

// REQ-DEFECTDOJO-001 REQ-DEFECTDOJO-002 REQ-DEFECTDOJO-003 REQ-DEFECTDOJO-004 REQ-DEFECTDOJO-005 REQ-DEFECTDOJO-006
func TestDefectDojoExport(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	sigs := filepath.Join(c.dir, "sigs")
	if err := os.MkdirAll(sigs, 0o700); err != nil {
		t.Fatal(err)
	}
	sig := "- id: admin-console\n  name: Admin console\n  kind: admin-panel\n  confidence: 80\n  match:\n    all:\n      - { type: title_regex, value: 'Admin console' }\n"
	if err := os.WriteFile(filepath.Join(sigs, "s.yaml"), []byte(sig), 0o600); err != nil {
		t.Fatal(err)
	}
	c.net.up("192.0.2.1", 80)
	c.net.title("192.0.2.1", "Admin console")
	c.net.up("192.0.2.2", 22)
	c.scan("d1", "--signatures-dir", sigs)

	d := &dojoServer{}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)

	code, _, stderr := c.runDojo(srv, "", "defectdojo", "export", "--run", "d1")
	assertOneLineError(t, "unconfigured export", code, stderr, "not configured")

	dry := filepath.Join(c.dir, "dry")
	code, stdout, stderr := c.runDojo(srv, "", "defectdojo", "export", "--run", "d1", "--dry-run", "--out", dry)
	if code != 0 || !strings.Contains(stdout, "2 hosts, 2 services") || !strings.Contains(stdout, "1 findings") || !strings.Contains(stdout, defectdojo.ImportPath) {
		t.Fatalf("dry run: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	dryXML, err := os.ReadFile(filepath.Join(dry, defectdojo.NmapFile))
	if err != nil || !bytes.Contains(dryXML, []byte(`<nmaprun scanner="nmap"`)) || !bytes.Contains(dryXML, []byte(`portid="22"`)) {
		t.Fatalf("dry nmap.xml: %v\n%s", err, dryXML)
	}
	dryJSON, err := os.ReadFile(filepath.Join(dry, defectdojo.FindingsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(dryJSON, []byte(`"unique_id_from_tool": "asi:192.0.2.2:tcp/22"`)) {
		t.Fatalf("dry run has no open service finding for 192.0.2.2:22:\n%s", dryJSON)
	}
	firstIDs := uniqueIDs(t, dryJSON)
	if len(firstIDs) != 1 || firstIDs[0] != "asi:192.0.2.1:tcp/80:admin-console" {
		t.Fatalf("dry run ids = %v", firstIDs)
	}
	if calls := d.take(); len(calls) != 0 {
		t.Fatalf("dry run sent %d requests", len(calls))
	}

	code, stdout, stderr = c.runDojo(srv, dojoToken+"\n", "defectdojo", "configure", "--url", srv.URL+"/", "--product", "4", "--engagement", "5", "--token-stdin")
	if code != 0 || strings.Contains(stdout+stderr, dojoToken) {
		t.Fatalf("configure: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	var raw []byte
	if err := c.st.Pool.QueryRow(context.Background(), `SELECT value FROM settings WHERE key = 'defectdojo'`).Scan(&raw); err != nil || bytes.Contains(raw, []byte(dojoToken)) {
		t.Fatalf("stored settings: %v, plain token %v", err, bytes.Contains(raw, []byte(dojoToken)))
	}

	if calls := d.take(); len(calls) != 1 || calls[0].path != "/api/v2/engagements/5/" {
		t.Fatalf("configure did not run the connection test: %+v", calls)
	}

	code, stdout, _ = c.runDojo(srv, "", "defectdojo", "test")
	if code != 0 || stdout != "defectdojo: connection ok\n" {
		t.Fatalf("test: exit %d stdout %q", code, stdout)
	}
	if calls := d.take(); len(calls) != 1 || calls[0].method != http.MethodGet || calls[0].auth != "Token "+dojoToken {
		t.Fatalf("test calls %+v", calls)
	}

	code, stdout, stderr = c.runDojo(srv, "", "defectdojo", "export", "--run", "d1")
	if code != 0 || !strings.Contains(stdout, "to test 101") || !strings.Contains(stdout, "to test 102") {
		t.Fatalf("first export: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	calls := d.take()
	if len(calls) != 2 || calls[0].path != defectdojo.ImportPath || calls[1].path != defectdojo.ImportPath ||
		calls[0].fields["scan_type"] != "Nmap Scan" || calls[0].fields["engagement"] != "5" ||
		calls[1].fields["scan_type"] != "Generic Findings Import" || calls[1].fields["engagement"] != "5" {
		t.Fatalf("first export calls %+v", calls)
	}

	c.net.title("192.0.2.1", "Admin console v2")
	c.scan("d2", "--signatures-dir", sigs)
	code, stdout, stderr = c.runDojo(srv, "", "defectdojo", "export", "--run", "d2")
	if code != 0 {
		t.Fatalf("second export: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	calls = d.take()
	if len(calls) != 2 || calls[0].path != defectdojo.ReimportPath || calls[0].fields["test"] != "101" ||
		calls[1].path != defectdojo.ReimportPath || calls[1].fields["test"] != "102" {
		t.Fatalf("second export calls %+v", calls)
	}
	if ids := uniqueIDs(t, calls[1].file); len(ids) != 1 || ids[0] != firstIDs[0] {
		t.Fatalf("re-export ids %v, want %v", ids, firstIDs)
	}

	d.status = http.StatusUnauthorized
	code, _, stderr = c.runDojo(srv, "", "defectdojo", "export", "--run", "d2")
	assertOneLineError(t, "rejected export", code, stderr, "401")
	if strings.Contains(stderr, dojoToken) {
		t.Fatalf("stderr leaks the token: %q", stderr)
	}
	code, _, stderr = c.runDojo(srv, "", "defectdojo", "export", "--run", "nope")
	assertOneLineError(t, "unknown run", code, stderr, `unknown run "nope"`)
}
