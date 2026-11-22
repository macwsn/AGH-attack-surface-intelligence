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
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/inventory"
)

type detections struct {
	Technologies []inventory.Technology
	Findings     []inventory.Finding
}

func hostDetections(t *testing.T, exp inventory.Export, addr string) []detections {
	t.Helper()
	h, ok := hostByAddr(exp, addr)
	if !ok {
		t.Fatalf("host %s missing from export", addr)
	}
	var out []detections
	for _, s := range h.Services {
		out = append(out, detections{s.Technologies, s.Findings})
	}
	return out
}

// R11 AC1 AC2: asi serve hands the web layer the signature set, so a UI import and a manual entry match signatures
// exactly like asi import of the same data.
func TestServeUIImportAndManualEntryMatchSignaturesLikeCLIImport(t *testing.T) {
	sigDir := t.TempDir()
	sig := "- id: shop-title\n  name: Shop\n  kind: technology\n  confidence: 70\n  match:\n    all:\n      - { type: title_regex, value: 'Shop' }\n" +
		"- id: admin-console\n  name: Admin console\n  kind: admin-panel\n  confidence: 80\n  match:\n    all:\n      - { type: title_regex, value: 'Admin console' }\n"
	if err := os.WriteFile(filepath.Join(sigDir, "s.yaml"), []byte(sig), 0o600); err != nil {
		t.Fatal(err)
	}
	csvData := "address,port,protocol,service,scheme,status_code,title\n" +
		"192.0.2.1,80,tcp,http,http,200,Shop Admin console\n" +
		"192.0.2.2,80,tcp,http,http,200,Shop Admin console\n"

	cli := newCLIEnv(t, "192.0.2.0/29", "")
	file := filepath.Join(cli.dir, "hosts.csv")
	if err := os.WriteFile(file, []byte(csvData), 0o600); err != nil {
		t.Fatal(err)
	}
	cli.mustRun("import", "--format", "csv", "--file", file, "--name", "cli", "--signatures-dir", sigDir)
	want := hostDetections(t, cli.export(""), "192.0.2.1")
	if len(want) != 1 || len(want[0].Technologies) == 0 || len(want[0].Findings) == 0 {
		t.Fatalf("asi import matched no signatures: %+v", want)
	}

	ui := newCLIEnv(t, "192.0.2.0/29", "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ui.env["ASI_LISTEN"] = addr
	ui.env["ASI_SIGNATURES_DIR"] = sigDir
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		code, _, _ := ui.runCtx(ctx, ui.net.runner(), "serve")
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
	base := "http://" + addr
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

	svc := auth.NewService(ui.st, auth.Config{})
	actor := auth.Actor{Username: "test", Addr: "local"}
	if err := svc.CreateUser(ctx, actor, "edna", "edna-password-123", auth.RoleEditor); err != nil {
		t.Fatal(err)
	}
	sess, err := svc.Login(ctx, "edna", "edna-password-123", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	post := func(path, contentType string, body io.Reader) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, base+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set(auth.CSRFHeader, sess.CSRFToken)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sess.Token})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST %s = %d: %s", path, resp.StatusCode, b)
		}
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range map[string]string{"format": "csv", "name": "ui"} {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	fw, err := mw.CreateFormFile("file", "hosts.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(fw, strings.Join(strings.Split(csvData, "\n")[:2], "\n")+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	post("/import", mw.FormDataContentType(), &body)

	form := url.Values{"address": {"192.0.2.2"}, "port": {"80"}, "protocol": {"tcp"}, "service": {"http"},
		"scheme": {"http"}, "status_code": {"200"}, "title": {"Shop Admin console"}}
	post("/hosts/entry", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))

	exp := ui.export("")
	for _, c := range []struct{ path, addr string }{{"UI import", "192.0.2.1"}, {"manual entry", "192.0.2.2"}} {
		got := hostDetections(t, exp, c.addr)
		wantHost := hostDetections(t, cli.export(""), c.addr)
		if !reflect.DeepEqual(got, wantHost) {
			g, _ := json.Marshal(got)
			w, _ := json.Marshal(wantHost)
			t.Errorf("%s: technologies and findings differ from asi import\n got %s\nwant %s", c.path, g, w)
		}
	}
}
