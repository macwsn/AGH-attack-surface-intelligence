//go:build integration

package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asi/internal/exchange/defectdojo"
)

type realDojo struct {
	mu      sync.Mutex
	nextID  int
	tests   map[string]bool
	uploads []dojoCall
}

func (d *realDojo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call := dojoCall{method: r.Method, path: r.URL.Path, fields: map[string]string{}}
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
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodPost {
		d.uploads = append(d.uploads, call)
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/engagements/5/":
		fmt.Fprint(w, `{"id": 5, "product": 4}`)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v2/tests/"):
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/tests/"), "/")
		if !d.tests[id] {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"detail": "No Test matches the given query."}`)
			return
		}
		fmt.Fprintf(w, `{"id": %s, "engagement": 5}`, id)
	case r.URL.Path == defectdojo.ImportPath:
		d.nextID++
		id := 100 + d.nextID
		d.tests[strconv.Itoa(id)] = true
		fmt.Fprintf(w, `{"test_id": %d, "test": %d, "engagement_id": 5}`, id, id)
	case r.URL.Path == defectdojo.ReimportPath:
		id := call.fields["test"]
		if !d.tests[id] {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"test": ["Invalid pk \"%s\" - object does not exist."]}`, id)
			return
		}
		fmt.Fprintf(w, `{"test_id": %s, "test": %s}`, id, id)
	default:
		http.NotFound(w, r)
	}
}

func (d *realDojo) take() []dojoCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.uploads
	d.uploads = nil
	return out
}

// AC2 AC3 AC6 against an httptest DefectDojo through the CLI.
func TestDefectDojoFixesFromRealDojoRun(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	c.scan("d1")
	time.Sleep(1100 * time.Millisecond)
	c.scan("d2")

	d := &realDojo{tests: map[string]bool{}}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	code, stdout, stderr := c.runDojo(srv, dojoToken+"\n", "defectdojo", "configure", "--url", srv.URL, "--product", "4", "--engagement", "5", "--token-stdin")
	if code != 0 {
		t.Fatalf("configure: exit %d stdout %q stderr %q", code, stdout, stderr)
	}

	code, stdout, stderr = c.runDojo(srv, "", "defectdojo", "export", "--run", "d1")
	if code != 0 {
		t.Fatalf("export d1: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	var started time.Time
	if err := c.st.Pool.QueryRow(context.Background(), `SELECT started_at FROM runs WHERE name = 'd1'`).Scan(&started); err != nil {
		t.Fatal(err)
	}
	var root struct {
		Start int64 `xml:"start,attr"`
	}
	calls := d.take()
	if len(calls) != 2 {
		t.Fatalf("export d1 uploads %+v", calls)
	}
	if err := xml.Unmarshal(calls[0].file, &root); err != nil {
		t.Fatal(err)
	}
	if root.Start != started.Unix() {
		t.Fatalf("nmap xml start = %d, want the scan's start %d (run d1 started %s)", root.Start, started.Unix(), started)
	}

	code, stdout, stderr = c.runDojo(srv, "", "defectdojo", "export", "--run", "d2")
	if code != 0 {
		t.Fatalf("export d2: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	d.take()

	code, stdout, stderr = c.runDojo(srv, "", "defectdojo", "export", "--run", "d1")
	if code == 0 || !strings.Contains(strings.ToLower(stderr), "older") {
		t.Fatalf("export of a run older than the last exported one was not refused: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	if calls := d.take(); len(calls) != 0 {
		t.Fatalf("refused export sent %d uploads", len(calls))
	}
	code, stdout, stderr = c.runDojo(srv, "", "defectdojo", "export", "--run", "d1", "--force")
	if code != 0 {
		t.Fatalf("export d1 --force: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	d.take()

	d.mu.Lock()
	delete(d.tests, "101")
	d.mu.Unlock()
	code, stdout, stderr = c.runDojo(srv, "", "defectdojo", "test")
	if !strings.Contains(stdout+stderr, "101") {
		t.Fatalf("defectdojo test does not report the deleted stored test 101: exit %d stdout %q stderr %q", code, stdout, stderr)
	}

	code, stdout, stderr = c.runDojo(srv, "", "defectdojo", "export", "--run", "d2")
	if code != 0 || !strings.Contains(strings.ToLower(stdout), "recreated") {
		t.Fatalf("export with a deleted test: exit %d stdout %q stderr %q; want success saying the test was recreated", code, stdout, stderr)
	}
	imports := 0
	for _, call := range d.take() {
		if call.path == defectdojo.ImportPath {
			imports++
		}
	}
	if imports != 1 {
		t.Fatalf("deleted test recreated with %d imports, want 1", imports)
	}
}
