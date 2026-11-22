//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"asi/internal/detect"
	"asi/internal/diff"
	"asi/internal/inventory"
	"asi/internal/store"
)

func withoutTimes(exp inventory.Export) []inventory.ExportHost {
	hosts := exp.Hosts
	for i := range hosts {
		hosts[i].FirstSeen, hosts[i].LastSeen, hosts[i].Availability = time.Time{}, time.Time{}, nil
		for j := range hosts[i].Services {
			hosts[i].Services[j].FirstSeen, hosts[i].Services[j].LastSeen = time.Time{}, time.Time{}
		}
	}
	return hosts
}

// REQ-EXCHANGE-005 REQ-EXCHANGE-006 AC1 AC5: asi import --format json of an export into an empty database gives the same export.
func TestImportJSONRoundTripCLI(t *testing.T) {
	a := newCLIEnv(t, "192.0.2.0/29", "")
	a.net.up("192.0.2.1", 22, 80)
	a.net.up("192.0.2.2", 80)
	a.net.title("192.0.2.2", "=1+1")
	a.scan("s1")
	a.mustRun("host", "edit", "192.0.2.1", "--add-tag", "crown", "--notes", "web team")
	file := filepath.Join(a.dir, "export.json")
	a.mustRun("export", "--format", "json", "--out", file)
	want := a.export("")

	b := newCLIEnv(t, "192.0.2.0/29", "")
	out := b.mustRun("import", "--format", "json", "--file", file, "--name", "from-a")
	if !strings.Contains(out, "imported 2 hosts, 3 services as run from-a; 0 invalid rows") {
		t.Fatalf("stdout = %q", out)
	}
	got := b.export("")
	if got.Run != "from-a" {
		t.Fatalf("export run = %q", got.Run)
	}
	if !reflect.DeepEqual(withoutTimes(got), withoutTimes(want)) {
		g, _ := json.Marshal(got.Hosts)
		w, _ := json.Marshal(want.Hosts)
		t.Fatalf("round trip differs\n got %s\nwant %s", g, w)
	}
	run, err := b.inv.RunByName(t.Context(), "from-a")
	if err != nil || run.Source != inventory.SourceImport {
		t.Fatalf("run = %+v (%v)", run, err)
	}
}

// REQ-EXCHANGE-005 AC1 AC3: a CSV import is a run that takes part in asi diff; invalid rows are listed; a dry run records nothing.
func TestImportCSVDiffAndDryRunCLI(t *testing.T) {
	c := newCLIEnv(t, "192.0.2.0/29", "")
	c.net.up("192.0.2.1", 80)
	c.net.title("192.0.2.1", "Intranet v1")
	c.scan("s1")
	file := filepath.Join(c.dir, "hosts.csv")
	csvData := "address,port,protocol,service,scheme,status_code,title\n" +
		"192.0.2.1,80,tcp,http,http,200,Intranet v2\n" +
		"192.0.2.300,80,tcp,http,,,\n" +
		"192.0.2.5,,,,,,\n"
	if err := os.WriteFile(file, []byte(csvData), 0o600); err != nil {
		t.Fatal(err)
	}

	out := c.mustRun("import", "--format", "csv", "--file", file, "--name", "imp1", "--dry-run")
	for _, w := range []string{`Row 3: "192.0.2.300" is not an address.`, "dry run: would import 2 hosts, 1 services as run imp1; 1 invalid rows",
		"service_changed 192.0.2.1 80/tcp ", "http.title: Intranet v1 -> Intranet v2", "host_new 192.0.2.5"} {
		if !strings.Contains(out, w) {
			t.Errorf("dry run stdout lacks %q:\n%s", w, out)
		}
	}
	if n := countRuns(t, c.st); n != 1 {
		t.Fatalf("dry run created a run: %d runs", n)
	}

	out = c.mustRun("import", "--format", "csv", "--file", file, "--name", "imp1")
	if !strings.Contains(out, "imported 2 hosts, 1 services as run imp1; 1 invalid rows; 2 changes") {
		t.Fatalf("stdout = %q", out)
	}
	diffFile := filepath.Join(c.dir, "diff.json")
	c.mustRun("diff", "--from", "s1", "--to", "imp1", "--format", "json", "--out", diffFile)
	data, err := os.ReadFile(diffFile)
	if err != nil {
		t.Fatal(err)
	}
	var d diff.Diff
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	types := []string{}
	for _, ch := range d.Changes {
		types = append(types, ch.Type+" "+ch.Address)
	}
	if !reflect.DeepEqual(types, []string{"service_changed 192.0.2.1", "host_new 192.0.2.5"}) {
		t.Fatalf("diff s1 -> imp1 = %s", data)
	}

	c.scan("s2")
	if h, ok := hostByAddr(c.export(""), "192.0.2.1"); !ok || h.Services[0].HTTP.Title != "Intranet v1" {
		t.Fatalf("scan after import = %+v", h)
	}

	bad := filepath.Join(c.dir, "bad.csv")
	if err := os.WriteFile(bad, []byte("address\nnope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := c.run("import", "--format", "csv", "--file", bad)
	assertOneLineError(t, "no valid rows", code, stderr, "no valid rows")
	code, _, stderr = c.run("import", "--format", "csv", "--file", filepath.Join(c.dir, "missing.csv"))
	assertOneLineError(t, "missing file", code, stderr, "--file")
	for _, args := range [][]string{{"import", "--format", "csv"}, {"import", "--file", bad}} {
		code, _, stderr := c.run(args...)
		if code != 2 {
			t.Fatalf("%v: exit %d", args, code)
		}
		assertUsage(t, stderr)
	}
	if n := countRuns(t, c.st); n != 3 {
		t.Fatalf("runs = %d, want s1, imp1 and s2", n)
	}
}

// R11 AC1: with an enabled database signature next to the signatures directory, a UI import and a manual entry through
// asi serve give the same technologies and findings as asi import of the same data.
func TestUIImportAndEntryMatchDatabaseSignaturesLikeCLIImport(t *testing.T) {
	ctx := context.Background()
	sigDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sigDir, "s.yaml"), []byte("- id: dir-shop\n  name: Shop\n  kind: technology\n  confidence: 70\n  match: { all: [ { type: title_regex, value: 'Shop' } ] }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dbSig := "id: db-admin\nname: Admin console\nkind: admin-panel\nconfidence: 80\nmatch: { all: [ { type: title_regex, value: 'Admin' } ] }\n"
	enable := func(st *store.Store) {
		t.Helper()
		if _, err := detect.NewLibrary(st, testKeyring(t), "").Create(ctx, detect.Actor{Username: "test", Addr: "local"}, dbSig, true); err != nil {
			t.Fatal(err)
		}
	}
	row := "http,http,200,Shop Admin console\n"
	csvData := "address,port,protocol,service,scheme,status_code,title\n192.0.2.1,80,tcp," + row + "192.0.2.2,80,tcp," + row

	cli := newCLIEnv(t, "192.0.2.0/29", "")
	enable(cli.st)
	file := filepath.Join(cli.dir, "hosts.csv")
	if err := os.WriteFile(file, []byte(csvData), 0o600); err != nil {
		t.Fatal(err)
	}
	cli.mustRun("import", "--format", "csv", "--file", file, "--name", "cli", "--signatures-dir", sigDir)
	cliExp := cli.export("")

	ui := newCLIEnv(t, "192.0.2.0/29", "")
	enable(ui.st)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	ui.env["ASI_LISTEN"] = ln.Addr().String()
	ln.Close()
	ui.env["ASI_SIGNATURES_DIR"] = sigDir
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan int, 1)
	go func() {
		code, _, _ := ui.runCtx(sctx, ui.net.runner(), "serve")
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
	svc := auth.NewService(ui.st, auth.Config{})
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, "edna", "edna-password-123", auth.RoleEditor); err != nil {
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

	uiExp := ui.export("")
	for _, c := range []struct{ path, addr string }{{"UI import", "192.0.2.1"}, {"manual entry", "192.0.2.2"}} {
		want := hostDetections(t, cliExp, c.addr)
		var ids []string
		for _, f := range want[0].Findings {
			ids = append(ids, f.SignatureID)
		}
		if strings.Join(ids, ",") != "dir-shop,db-admin" {
			t.Fatalf("asi import findings for %s = %v, want dir-shop and db-admin", c.addr, ids)
		}
		if got := hostDetections(t, uiExp, c.addr); !reflect.DeepEqual(got, want) {
			g, _ := json.Marshal(got)
			w, _ := json.Marshal(want)
			t.Errorf("%s: technologies and findings differ from asi import\n got %s\nwant %s", c.path, g, w)
		}
	}
}

func testKeyring(t *testing.T) *store.Keyring {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatal(err)
	}
	k, err := store.NewKeyring(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
