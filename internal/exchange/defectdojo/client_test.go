package defectdojo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testToken = "s3cr3t-dojo-token"

type recorded struct {
	Method   string
	Path     string
	Auth     string
	Fields   map[string]string
	FileName string
	File     string
}

type fakeDojo struct {
	mu       sync.Mutex
	requests []recorded
	nextTest int
	status   int
	body     string
	product  int
}

func newFakeDojo(t *testing.T) (*fakeDojo, *httptest.Server) {
	t.Helper()
	f := &fakeDojo{nextTest: 40, product: 2}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeDojo) serve(w http.ResponseWriter, r *http.Request) {
	rec := recorded{Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Fields: map[string]string{}}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for k, v := range r.MultipartForm.Value {
			rec.Fields[k] = strings.Join(v, ",")
		}
		if fh := r.MultipartForm.File["file"]; len(fh) == 1 {
			rec.FileName = fh[0].Filename
			fd, _ := fh[0].Open()
			b, _ := io.ReadAll(fd)
			fd.Close()
			rec.File = string(b)
		}
	}
	f.mu.Lock()
	f.requests = append(f.requests, rec)
	status, body := f.status, f.body
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if status != 0 {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
		return
	}
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v2/engagements/"):
		fmt.Fprintf(w, `{"id": 3, "product": %d}`, f.product)
	case r.Method == http.MethodPost && r.URL.Path == ImportPath:
		f.mu.Lock()
		f.nextTest++
		id := f.nextTest
		f.mu.Unlock()
		fmt.Fprintf(w, `{"test": %d, "test_id": %d, "engagement_id": 3}`, id, id)
	case r.Method == http.MethodPost && r.URL.Path == ReimportPath:
		fmt.Fprintf(w, `{"test": %s, "test_id": %s}`, rec.Fields["test"], rec.Fields["test"])
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeDojo) calls() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.requests...)
}

func testClient(srv *httptest.Server) *Client {
	return &Client{BaseURL: srv.URL, Token: testToken, HTTP: srv.Client()}
}

func checkUpload(t *testing.T, got recorded, path string, fields map[string]string, fileName, file string) {
	t.Helper()
	if got.Method != http.MethodPost || got.Path != path {
		t.Fatalf("request = %s %s, want POST %s", got.Method, got.Path, path)
	}
	if got.Auth != "Token "+testToken {
		t.Fatalf("Authorization = %q", got.Auth)
	}
	for k, v := range fields {
		if got.Fields[k] != v {
			t.Fatalf("field %s = %q, want %q (all: %v)", k, got.Fields[k], v, got.Fields)
		}
	}
	if got.FileName != fileName || got.File != file {
		t.Fatalf("file = %q %q, want %q %q", got.FileName, got.File, fileName, file)
	}
}

// REQ-DEFECTDOJO-003 REQ-DEFECTDOJO-005
func TestImportSendsMultipart(t *testing.T) {
	f, srv := newFakeDojo(t)
	id, err := testClient(srv).Import(context.Background(), 3, Upload{ScanType: ScanTypeNmap, FileName: "nmap.xml", File: []byte("<nmaprun/>")})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if id != 41 {
		t.Fatalf("test id = %d, want 41", id)
	}
	calls := f.calls()
	if len(calls) != 1 {
		t.Fatalf("%d requests", len(calls))
	}
	checkUpload(t, calls[0], ImportPath, map[string]string{
		"scan_type": "Nmap Scan", "engagement": "3", "minimum_severity": "Info", "active": "true",
	}, "nmap.xml", "<nmaprun/>")
	if _, ok := calls[0].Fields["test"]; ok {
		t.Fatal("import sent a test field")
	}
}

// REQ-DEFECTDOJO-003
func TestReimportSendsTestID(t *testing.T) {
	f, srv := newFakeDojo(t)
	id, err := testClient(srv).Reimport(context.Background(), 77, Upload{ScanType: ScanTypeGeneric, FileName: "findings.json", File: []byte(`{"findings":[]}`)})
	if err != nil {
		t.Fatalf("Reimport: %v", err)
	}
	if id != 77 {
		t.Fatalf("test id = %d, want 77", id)
	}
	calls := f.calls()
	checkUpload(t, calls[0], ReimportPath, map[string]string{
		"scan_type": "Generic Findings Import", "test": "77", "minimum_severity": "Info",
	}, "findings.json", `{"findings":[]}`)
	if _, ok := calls[0].Fields["engagement"]; ok {
		t.Fatal("reimport sent an engagement field")
	}
}

// REQ-DEFECTDOJO-002
func TestCheckEngagement(t *testing.T) {
	f, srv := newFakeDojo(t)
	c := testClient(srv)
	if err := c.CheckEngagement(context.Background(), 2, 3); err != nil {
		t.Fatalf("CheckEngagement: %v", err)
	}
	got := f.calls()[0]
	if got.Method != http.MethodGet || got.Path != "/api/v2/engagements/3/" || got.Auth != "Token "+testToken {
		t.Fatalf("request = %+v", got)
	}
	err := c.CheckEngagement(context.Background(), 9, 3)
	if err == nil || !strings.Contains(err.Error(), "belongs to product 2, not 9") {
		t.Fatalf("product mismatch: %v", err)
	}
}

// REQ-DEFECTDOJO-005
func TestFailuresReportStatusWithoutToken(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusBadRequest, http.StatusInternalServerError} {
		f, srv := newFakeDojo(t)
		f.status = status
		f.body = `{"detail": "Invalid token header ` + testToken + `"}`
		c := testClient(srv)
		_, err := c.Import(context.Background(), 3, Upload{ScanType: ScanTypeNmap, FileName: "nmap.xml", File: []byte("x")})
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != status {
			t.Fatalf("status %d: err = %v", status, err)
		}
		msg := err.Error()
		if !strings.Contains(msg, fmt.Sprint(status)) || !strings.Contains(msg, ImportPath) || strings.Contains(msg, "Invalid token header") {
			t.Fatalf("status %d: message %q", status, msg)
		}
		if strings.Contains(msg, testToken) {
			t.Fatalf("status %d: message leaks the token: %q", status, msg)
		}
		if err := c.CheckEngagement(context.Background(), 2, 3); err == nil || strings.Contains(err.Error(), testToken) || !strings.Contains(err.Error(), fmt.Sprint(status)) {
			t.Fatalf("status %d: CheckEngagement err %v", status, err)
		}
	}
}

// REQ-DEFECTDOJO-005
func TestNetworkErrorHasNoToken(t *testing.T) {
	_, srv := newFakeDojo(t)
	srv.Close()
	err := testClient(srv).CheckEngagement(context.Background(), 2, 3)
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://dojo.example/":        "https://dojo.example",
		" http://10.0.0.5:8080/dojo/ ": "http://10.0.0.5:8080/dojo",
	} {
		got, err := NormalizeBaseURL(in)
		if err != nil || got != want {
			t.Errorf("NormalizeBaseURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "dojo.example", "ftp://dojo.example", "https://user:pw@dojo.example", "https://dojo.example/?a=1"} {
		if _, err := NormalizeBaseURL(in); err == nil {
			t.Errorf("NormalizeBaseURL(%q) accepted", in)
		}
	}
}

// REQ-DEFECTDOJO-005
func TestErrorBodyIsTrimmedAndWithoutToken(t *testing.T) {
	c := &Client{Token: testToken}
	long := `{"detail": "` + strings.Repeat("x", 400) + `"}`
	if got := c.errorBody([]byte(long)); len(got) > maxErrorBody+len("…") || !strings.HasSuffix(got, "…") {
		t.Fatalf("long body = %q", got)
	}
	for body, want := range map[string]string{
		`{"test": ["Invalid pk"], "list": ["` + testToken + `", "kept"]}`: `{"list":["kept"],"test":["Invalid pk"]}`,
		"<html>\n  oops " + testToken + "</html>":                         "",
		"<html>\n  Bad   gateway</html>":                                  "<html> Bad gateway</html>",
		`{"detail": "token ` + testToken + `"}`:                           "",
	} {
		if got := c.errorBody([]byte(body)); got != want {
			t.Errorf("errorBody(%q) = %q, want %q", body, got, want)
		}
	}
	missing := []*APIError{
		{Status: http.StatusNotFound, Body: `{"detail":"Not found."}`},
		{Status: http.StatusBadRequest, Body: `{"test":["Invalid pk \"4\" - object does not exist."]}`},
	}
	for _, e := range missing {
		if !e.testMissing() {
			t.Errorf("%+v is not a missing test", e)
		}
	}
	for _, e := range []*APIError{
		{Status: http.StatusNotFound, NotAPI: true},
		{Status: http.StatusBadRequest, Body: `{"engagement":["Engagement is closed"]}`},
		{Status: http.StatusInternalServerError, Body: `{"test":["does not exist"]}`},
	} {
		if e.testMissing() {
			t.Errorf("%+v taken for a missing test", e)
		}
	}
	e := &APIError{Method: "GET", Path: "/x/", Status: http.StatusBadGateway, NotAPI: true, Body: "<html> Bad gateway</html>"}
	if !strings.Contains(e.Error(), "does not look like a DefectDojo API") || !strings.Contains(e.Error(), "Bad gateway") {
		t.Fatalf("non-JSON error = %q", e.Error())
	}
}

// REQ-DEFECTDOJO-002 REQ-DEFECTDOJO-008
func TestConnectionChecksStoredTests(t *testing.T) {
	svc, m, f := newService(t)
	m.s.NmapTestID, m.s.FindingsTestID = 41, 42
	client := svc.HTTP
	svc.HTTP = doerFunc(func(req *http.Request) (*http.Response, error) {
		f.mu.Lock()
		f.status, f.body = 0, ""
		switch req.URL.Path {
		case "/api/v2/tests/41/":
			f.status, f.body = http.StatusOK, `{"id": 41}`
		case "/api/v2/tests/42/":
			f.status, f.body = http.StatusNotFound, `{"detail": "No Test matches the given query."}`
		}
		f.mu.Unlock()
		return client.Do(req)
	})
	if err := svc.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	err := svc.CheckStoredTests(context.Background())
	if !errors.Is(err, ErrTestsMissing) || !strings.Contains(err.Error(), "findings test 42") || strings.Contains(err.Error(), "test 41") {
		t.Fatalf("TestConnection with a deleted test = %v", err)
	}
	c := &Client{BaseURL: m.s.BaseURL, Token: testToken, HTTP: svc.HTTP}
	if ok, err := c.TestExists(context.Background(), 41); !ok || err != nil {
		t.Fatalf("TestExists(41) = %v, %v", ok, err)
	}
	c.HTTP = client
	f.status = 0
	if ok, err := c.TestExists(context.Background(), 41); ok || err == nil {
		t.Fatalf("TestExists on a non-JSON 404 = %v, %v", ok, err)
	}
}
