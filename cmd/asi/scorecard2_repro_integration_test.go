//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/diff"
	"asi/internal/exchange/defectdojo"
	"asi/internal/inventory"
)

// AC2: inactive_after=2, host missed twice, import of another host, rescan -> no second host_inactive.
func TestReproImportDoesNotFlapInactiveHostAndNextScanDoesNotReportItAgain(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	c.net.up("192.0.2.2", 80)
	c.scan("s1", "--inactive-after", "2")
	c.net.down("192.0.2.1")
	c.scan("s2", "--inactive-after", "2")
	c.scan("s3", "--inactive-after", "2")
	if h, ok := hostByAddr(c.export("s3"), "192.0.2.1"); !ok || h.Status != inventory.StatusInactive {
		t.Fatalf("precondition: 192.0.2.1 after two missed runs with inactive_after=2 = %+v, want inactive", h)
	}

	file := filepath.Join(c.dir, "other.csv")
	if err := os.WriteFile(file, []byte("address,port,protocol,service\n192.0.2.5,80,tcp,http\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.mustRun("import", "--format", "csv", "--file", file, "--name", "imp")
	if h, ok := hostByAddr(c.export("imp"), "192.0.2.1"); !ok || h.Status != inventory.StatusInactive {
		t.Errorf("import of another host changed the status of 192.0.2.1 to %q, want inactive", h.Status)
	}
	for _, ch := range c.diffDoc("s3", "imp").Changes {
		if ch.Address == "192.0.2.1" {
			t.Errorf("import of another host reports a change for 192.0.2.1: %+v", ch)
		}
	}

	c.scan("s4", "--inactive-after", "2")
	for _, ch := range c.diffDoc("imp", "s4").Changes {
		if ch.Address == "192.0.2.1" && ch.Type == diff.HostInactive {
			t.Errorf("scan after the import reports 192.0.2.1 inactive a second time: %+v", ch)
		}
	}
}

// AC4: asi defectdojo export --run NAME --dry-run contains only the hosts and services that run covered.
func TestReproDefectDojoDryRunContainsOnlyHostsTheRunCovered(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	c.net.up("192.0.2.2", 22)
	c.scan("d1")
	if err := os.WriteFile(c.targets, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.scan("d2")

	srv := httptest.NewServer(&dojoServer{})
	t.Cleanup(srv.Close)
	dry := filepath.Join(c.dir, "dry")
	code, stdout, stderr := c.runDojo(srv, "", "defectdojo", "export", "--run", "d2", "--dry-run", "--out", dry)
	if code != 0 {
		t.Fatalf("dry run: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "(1 hosts, 1 services)") {
		t.Errorf("dry run of a run covering only 192.0.2.1 reports %q, want (1 hosts, 1 services)", stdout)
	}
	for _, name := range []string{defectdojo.NmapFile, defectdojo.FindingsFile} {
		data, err := os.ReadFile(filepath.Join(dry, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "192.0.2.2") {
			t.Errorf("%s of run d2 carries 192.0.2.2, which d2 did not cover", name)
		}
	}
}

// AC5: asi export and asi diff write their status line to stderr, so stdout stays clean JSON/CSV with --out /dev/stdout.
func TestReproExportAndDiffStatusLineGoesToStderr(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	c.net.up("192.0.2.1", 80)
	c.scan("e1")
	c.scan("e2")
	for _, args := range [][]string{
		{"export", "--format", "json", "--out", filepath.Join(c.dir, "e.json")},
		{"export", "--format", "csv", "--out", filepath.Join(c.dir, "e.csv")},
		{"diff", "--from", "e1", "--to", "e2", "--format", "json", "--out", filepath.Join(c.dir, "d.json")},
	} {
		code, stdout, stderr := c.run(args...)
		if code != 0 {
			t.Fatalf("%v: exit %d stderr %q", args, code, stderr)
		}
		if stdout != "" {
			t.Errorf("%v: status line on stdout %q, want it on stderr", args, stdout)
		}
		if !strings.Contains(stderr, "exported ") && !strings.Contains(stderr, "changes from e1 to e2") {
			t.Errorf("%v: stderr %q lacks the status line", args, stderr)
		}
	}
	var d diff.Diff
	data, err := os.ReadFile(filepath.Join(c.dir, "d.json"))
	if err != nil || json.Unmarshal(data, &d) != nil {
		t.Fatalf("diff file: %v\n%s", err, data)
	}
}

func (c *cliEnv) serveUI(t *testing.T) (get func(path string) (int, string), post func(path, contentType string, body io.Reader, csrfHeader bool) (int, string)) {
	t.Helper()
	ctx := context.Background()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	c.env["ASI_LISTEN"] = ln.Addr().String()
	ln.Close()
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan int, 1)
	go func() {
		code, _, _ := c.runCtx(sctx, c.net.runner(), "serve")
		done <- code
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("serve did not stop")
		}
	})
	for i := range 50 {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if i == 49 {
			t.Fatalf("GET /healthz: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	svc := auth.NewService(c.st, auth.Config{})
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, "ada", "ada-password-123", auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	sess, err := svc.Login(ctx, "ada", "ada-password-123", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	do := func(req *http.Request) (int, string) {
		t.Helper()
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sess.Token})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	get = func(path string) (int, string) {
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		return do(req)
	}
	post = func(path, contentType string, body io.Reader, csrfHeader bool) (int, string) {
		req, err := http.NewRequest(http.MethodPost, base+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		if csrfHeader {
			req.Header.Set(auth.CSRFHeader, sess.CSRFToken)
		}
		return do(req)
	}
	return get, post
}

var csrfInputRe = regexp.MustCompile(`<input[^>]*name="csrf_token"[^>]*value="([^"]+)"|<input[^>]*value="([^"]+)"[^>]*name="csrf_token"`)

func formsOf(page string) []string {
	var out []string
	for _, part := range strings.Split(page, "<form")[1:] {
		form, _, _ := strings.Cut(part, "</form>")
		out = append(out, form)
	}
	return out
}

func csrfOf(form string) string {
	m := csrfInputRe.FindStringSubmatch(form)
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// AC5: the import form carries the CSRF token as a hidden field, a plain multipart POST works and the counts are
// pluralised; AC5: the host page links to its timeline; AC4: the DefectDojo page offers a Preview with counts.
func TestReproImportFormCSRFPluralHostTimelineAndDojoPreview(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "192.0.2.0")
	get, post := c.serveUI(t)

	code, page := get("/import")
	if code != http.StatusOK {
		t.Fatalf("GET /import = %d", code)
	}
	var importForm string
	for _, f := range formsOf(page) {
		if strings.Contains(f, `action="/import"`) {
			importForm = f
		}
	}
	token := csrfOf(importForm)
	if token == "" {
		t.Errorf("import form has no hidden csrf_token field:\n<form%s", importForm)
		for _, f := range formsOf(page) {
			if token == "" {
				token = csrfOf(f)
			}
		}
	}

	upload := func(csrfHeader bool) (int, string) {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		for k, v := range map[string]string{"csrf_token": token, "format": "csv", "name": "ui"} {
			if err := mw.WriteField(k, v); err != nil {
				t.Fatal(err)
			}
		}
		fw, err := mw.CreateFormFile("file", "hosts.csv")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(fw, "address,port,protocol,service,scheme,status_code,title\n192.0.2.5,80,tcp,http,http,200,Intranet\n"); err != nil {
			t.Fatal(err)
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		return post("/import", mw.FormDataContentType(), &body, csrfHeader)
	}
	code, page = upload(false)
	if code != http.StatusOK {
		t.Errorf("plain multipart POST /import with the form's csrf_token = %d: %s", code, regexp.MustCompile(`<p[^>]*>[^<]*`).FindAllString(page, -1))
		if code, page = upload(true); code != http.StatusOK {
			t.Fatalf("POST /import with the CSRF header = %d", code)
		}
	}
	if !strings.Contains(page, "1 host and 1 service") {
		t.Errorf("import result is not pluralised, want \"1 host and 1 service\": %s", regexp.MustCompile(`Imported [^<]*`).FindString(page))
	}

	if code, page = get("/hosts/192.0.2.5"); code != http.StatusOK || !strings.Contains(page, `href="/hosts/192.0.2.5/timeline"`) {
		t.Errorf("host page (%d) does not link to /hosts/192.0.2.5/timeline", code)
	}

	code, page = get("/defectdojo")
	if code != http.StatusOK {
		t.Fatalf("GET /defectdojo = %d", code)
	}
	var preview string
	for _, f := range formsOf(page) {
		if strings.Contains(f, "Preview") {
			preview = f
		}
	}
	if preview == "" {
		t.Errorf("DefectDojo page offers no Preview (dry run) form")
		return
	}
	action := regexp.MustCompile(`action="([^"]+)"`).FindStringSubmatch(preview)
	if action == nil {
		t.Fatalf("Preview form has no action: %s", preview)
	}
	form := url.Values{"csrf_token": {csrfOf(preview)}, "run": {"ui"}}
	for _, m := range regexp.MustCompile(`<button[^>]*name="([^"]+)"[^>]*value="([^"]*)"[^>]*>[^<]*Preview`).FindAllStringSubmatch(preview, -1) {
		form.Set(m[1], m[2])
	}
	code, page = post(action[1], "application/x-www-form-urlencoded", strings.NewReader(form.Encode()), false)
	if code != http.StatusOK || !regexp.MustCompile(`(?i)\b\d+ tests?\b`).MatchString(page) || !regexp.MustCompile(`(?i)\b\d+ findings?\b`).MatchString(page) {
		t.Errorf("Preview = %d, want counts of tests and findings that would be sent:\n%s", code, page)
	}
}
