//go:build integration

package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/inventory"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

type exchangeEnv struct {
	t   *testing.T
	h   http.Handler
	svc *auth.Service
	inv *inventory.Inventory
	st  *store.Store
}

func newExchangeEnv(t *testing.T) *exchangeEnv {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(st, auth.Config{})
	for user, role := range map[string]string{"edna": auth.RoleEditor, "olga": auth.RoleOperator, "vera": auth.RoleViewer} {
		if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, user, user+"-password-123", role); err != nil {
			t.Fatal(err)
		}
	}
	sigs, err := detect.Parse([]byte("- id: shop-title\n  name: Shop\n  kind: technology\n  confidence: 70\n  match: { all: [ { type: title_regex, value: 'Shop' } ] }\n"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc, Signatures: &detect.Set{Signatures: sigs}})
	if err != nil {
		t.Fatal(err)
	}
	return &exchangeEnv{t: t, h: h, svc: svc, inv: inventory.New(st, keys), st: st}
}

type session struct {
	cookie *http.Cookie
	csrf   string
}

func (e *exchangeEnv) login(user string) session {
	e.t.Helper()
	s, err := e.svc.Login(context.Background(), user, user+"-password-123", "127.0.0.1")
	if err != nil {
		e.t.Fatal(err)
	}
	return session{&http.Cookie{Name: auth.SessionCookieName, Value: s.Token}, s.CSRFToken}
}

func (e *exchangeEnv) serve(req *http.Request, s session) *httptest.ResponseRecorder {
	req.AddCookie(s.cookie)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func uploadRequest(t *testing.T, fields map[string]string, filename string, file []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(file); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/import", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func (e *exchangeEnv) upload(s session, fields map[string]string, filename string, file []byte) *httptest.ResponseRecorder {
	e.t.Helper()
	req := uploadRequest(e.t, fields, filename, file)
	req.Header.Set(auth.CSRFHeader, s.csrf)
	return e.serve(req, s)
}

func (e *exchangeEnv) runs() int {
	e.t.Helper()
	var n int
	if err := e.st.Pool.QueryRow(context.Background(), `SELECT count(*) FROM runs`).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

const twoHosts = `{"schema":"asi.export/v1","hosts":[
	{"address":"10.0.0.1","tags":["dmz"],"services":[{"port":80,"protocol":"tcp","service":"http","http":{"scheme":"http","status_code":200,"title":"=1+1 Shop"}}]},
	{"address":"10.0.0.2"},
	{"address":"10.0.0.300"}]}`

// REQ-EXCHANGE-007 REQ-EXCHANGE-008 REQ-WEB-005 AC1 AC3 AC4: the UI upload imports asi.export/v1 JSON as a run, reports invalid rows, supports a dry run and never
// writes the upload to disk.
func TestUploadImportsInMemory(t *testing.T) {
	e := newExchangeEnv(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	edna := e.login("edna")

	rec := e.upload(edna, map[string]string{"format": "json", "dry_run": "1"}, "hosts.json", []byte(twoHosts))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Dry run: 2 hosts and 1 service would be imported") ||
		!strings.Contains(body, `<tr><td class="num">3</td><td>&#34;10.0.0.300&#34; is not an address.</td></tr>`) ||
		!strings.Contains(body, `<span class="change new">New host</span>`) {
		t.Fatalf("dry run = %d\n%s", rec.Code, body)
	}
	if e.runs() != 0 {
		t.Fatalf("dry run recorded a run")
	}

	rec = e.upload(edna, map[string]string{"name": "upload-1"}, "hosts.json", []byte(twoHosts))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Imported 2 hosts and 1 service as run <code>upload-1</code>") {
		t.Fatalf("import = %d\n%s", rec.Code, rec.Body.String())
	}
	run, err := e.inv.RunByName(context.Background(), "upload-1")
	if err != nil || run.Source != inventory.SourceImport {
		t.Fatalf("run = %+v (%v)", run, err)
	}
	exp, err := e.inv.Export(context.Background(), "")
	if err != nil || len(exp.Hosts) != 2 || exp.Hosts[0].Services[0].Findings[0].SignatureID != "shop-title" {
		t.Fatalf("export after upload = %+v (%v)", exp, err)
	}

	big := append([]byte(`{"schema":"asi.export/v1","pad":"`), bytes.Repeat([]byte("x"), 19<<20)...)
	big = append(big, `","hosts":[{"address":"10.0.0.7"}]}`...)
	rec = e.upload(edna, map[string]string{"format": "json"}, "big.json", big)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Imported 1 host ") {
		t.Fatalf("19 MiB upload = %d", rec.Code)
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Fatalf("upload wrote %d files to TMPDIR", len(entries))
	}
	control := uploadRequest(t, nil, "big.json", big)
	if err := control.ParseMultipartForm(1 << 20); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(tmp); len(entries) == 0 {
		t.Fatal("control: ParseMultipartForm did not spool to TMPDIR, so the check above proves nothing")
	}
	control.MultipartForm.RemoveAll()

	tooBig := make([]byte, 20<<20+1)
	rec = e.upload(edna, map[string]string{"format": "json"}, "huge.json", tooBig)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "larger than 20 MiB") {
		t.Fatalf("20 MiB + 1 upload = %d", rec.Code)
	}

	for name, fields := range map[string]map[string]string{"no token": nil, "wrong token": {auth.CSRFFormField: "x" + edna.csrf}} {
		req := uploadRequest(t, fields, "hosts.json", []byte(twoHosts))
		if rec := e.serve(req, edna); rec.Code != http.StatusForbidden {
			t.Fatalf("multipart upload without the CSRF header, %s = %d, want 403", name, rec.Code)
		}
	}
	if e.runs() != 2 {
		t.Fatalf("runs = %d, want 2", e.runs())
	}
	req := uploadRequest(t, map[string]string{auth.CSRFFormField: edna.csrf, "name": "no-js"}, "hosts.json", []byte(twoHosts))
	if rec := e.serve(req, edna); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "as run <code>no-js</code>") {
		t.Fatalf("multipart upload with the CSRF field and no header = %d, want 200 (works without JavaScript)\n%s", rec.Code, rec.Body)
	}
}

// REQ-EXCHANGE-008 AC6: export as JSON and CSV for the current filter needs the export permission; import needs import.
func TestExportAndImportPermissions(t *testing.T) {
	e := newExchangeEnv(t)
	edna, olga, vera := e.login("edna"), e.login("olga"), e.login("vera")
	if rec := e.upload(edna, map[string]string{"name": "seed"}, "hosts.json", []byte(twoHosts)); rec.Code != http.StatusOK {
		t.Fatalf("seed = %d", rec.Code)
	}

	if rec := e.upload(olga, nil, "hosts.json", []byte(twoHosts)); rec.Code != http.StatusForbidden {
		t.Fatalf("operator upload = %d, want 403", rec.Code)
	}
	if rec := e.serve(httptest.NewRequest(http.MethodGet, "/import", nil), olga); rec.Code != http.StatusForbidden {
		t.Fatalf("operator GET /import = %d, want 403", rec.Code)
	}
	for _, path := range []string{"/export", "/export.json", "/export.csv"} {
		if rec := e.serve(httptest.NewRequest(http.MethodGet, path, nil), vera); rec.Code != http.StatusForbidden {
			t.Fatalf("viewer GET %s = %d, want 403", path, rec.Code)
		}
	}

	page := e.serve(httptest.NewRequest(http.MethodGet, "/export?tag=dmz", nil), olga)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "1 hosts match as of run <code>seed</code>") ||
		!strings.Contains(page.Body.String(), `formaction="/export.csv"`) {
		t.Fatalf("export page = %d\n%s", page.Code, page.Body.String())
	}

	rec := e.serve(httptest.NewRequest(http.MethodGet, "/export.json?"+url.Values{"q": {"10.0.0.2"}}.Encode(), nil), olga)
	var exp inventory.Export
	if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil || rec.Code != http.StatusOK || exp.Schema != "asi.export/v1" ||
		len(exp.Hosts) != 1 || exp.Hosts[0].Address != "10.0.0.2" {
		t.Fatalf("export.json?q = %d %v %s", rec.Code, err, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="asi-export-seed.json"` {
		t.Errorf("Content-Disposition = %q", cd)
	}

	rec = e.serve(httptest.NewRequest(http.MethodGet, "/export.csv?status=active&tag=dmz", nil), olga)
	rows, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil || rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") || len(rows) != 2 {
		t.Fatalf("export.csv = %d %v %v", rec.Code, err, rows)
	}
	if rows[1][0] != "10.0.0.1" || rows[1][10] != "'=1+1 Shop" {
		t.Fatalf("csv row = %v", rows[1])
	}
	if rec := e.serve(httptest.NewRequest(http.MethodGet, "/export.csv?run=nope", nil), olga); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown run = %d", rec.Code)
	}
}

// REQ-EXCHANGE-008 AC2: the manual form adds and edits a host through the import path.
func TestManualHostForm(t *testing.T) {
	e := newExchangeEnv(t)
	edna, olga := e.login("edna"), e.login("olga")
	post := func(s session, v url.Values) *httptest.ResponseRecorder {
		v.Set(auth.CSRFFormField, s.csrf)
		req := httptest.NewRequest(http.MethodPost, "/hosts/entry", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return e.serve(req, s)
	}
	form := url.Values{"address": {"10.0.0.9"}, "hostnames": {"shop.example"}, "tags": {"crown, dmz"},
		"port": {"80", "", "99999"}, "service": {"http", "", ""}, "scheme": {"http", "", ""}, "title": {"Shop", "", ""}}
	if rec := post(olga, form); rec.Code != http.StatusForbidden {
		t.Fatalf("operator POST = %d, want 403", rec.Code)
	}
	rec := post(edna, form)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "port 99999 is out of range 1-65535.") ||
		!strings.Contains(rec.Body.String(), "Imported 1 host and 1 service") {
		t.Fatalf("POST = %d\n%s", rec.Code, rec.Body.String())
	}
	exp, err := e.inv.Export(context.Background(), "")
	if err != nil || len(exp.Hosts) != 1 {
		t.Fatalf("export = %+v %v", exp, err)
	}
	run, err := e.inv.RunByName(context.Background(), exp.Run)
	if err != nil || run.Source != inventory.SourceManual {
		t.Fatalf("run = %+v (%v)", run, err)
	}
	if s := exp.Hosts[0].Services[0]; len(s.Findings) != 1 || s.Findings[0].SignatureID != "shop-title" {
		t.Fatalf("service = %+v", s)
	}

	page := e.serve(httptest.NewRequest(http.MethodGet, "/hosts/entry?address=10.0.0.9", nil), edna)
	body, _ := io.ReadAll(page.Body)
	for _, want := range []string{`name="address" value="10.0.0.9"`, `name="tags" value="crown, dmz"`, `name="title" value="Shop"`, `name="findings" value="shop-title"`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("edit form lacks %s\n%s", want, body)
		}
	}
	if !strings.Contains(string(body), `name="editing" value="10.0.0.9"`) {
		t.Fatalf("edit form is not in edit mode")
	}
	runs := e.runs()
	add := post(edna, url.Values{"address": {"10.0.0.9"}, "port": {"22"}, "service": {"ssh"}})
	if add.Code != http.StatusConflict || !strings.Contains(add.Body.String(), `<a href="/hosts/entry?address=10.0.0.9">Edit host 10.0.0.9</a>`) || e.runs() != runs {
		t.Fatalf("add of an existing address = %d, runs %d -> %d\n%s", add.Code, runs, e.runs(), add.Body.String())
	}
	if h, _ := e.inv.GetHostUserFields(context.Background(), "10.0.0.9"); len(h.Tags) != 2 {
		t.Fatalf("add of an existing address changed tags: %+v", h)
	}
	if rec := e.serve(httptest.NewRequest(http.MethodGet, "/hosts/entry?address=10.0.0.9", nil), olga); rec.Code != http.StatusForbidden {
		t.Fatalf("operator edit form = %d, want 403", rec.Code)
	}
	rec = post(edna, url.Values{"editing": {"10.0.0.9"}, "address": {"10.0.0.9"}, "tags": {"dmz"}, "port": {"80"}, "service": {"http"}, "scheme": {"http"}, "title": {"Shop 2"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<span class="change changed">Changed</span>`) {
		t.Fatalf("edit = %d\n%s", rec.Code, rec.Body.String())
	}
	exp, _ = e.inv.Export(context.Background(), "")
	if h := exp.Hosts[0]; len(h.Tags) != 1 || h.Tags[0] != "dmz" || h.Services[0].HTTP.Title != "Shop 2" {
		t.Fatalf("edited host = %+v", h)
	}
	if rec := e.serve(httptest.NewRequest(http.MethodGet, "/hosts/entry?address=10.9.9.9", nil), edna); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host = %d", rec.Code)
	}
}

// R11 AC2: with the shared detect.Library the UI import matches the directory signatures and the database signatures
// enabled after the handler was built, the same set the scheduler's scans use.
func TestUploadMatchesSharedLibrarySignatures(t *testing.T) {
	e := newExchangeEnv(t)
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/s.yaml", []byte("- id: dir-shop\n  name: Shop\n  kind: technology\n  confidence: 70\n  match: { all: [ { type: title_regex, value: 'Shop' } ] }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	lib := detect.NewLibrary(e.st, keys, dir)
	if e.h, err = New(Deps{Store: e.st, Keyring: keys, Auth: e.svc, Library: lib}); err != nil {
		t.Fatal(err)
	}
	e.inv = inventory.New(e.st, keys)
	if _, err := lib.Create(ctx, detect.Actor{Username: "test", Addr: "local"},
		"id: db-admin\nname: Admin console\nkind: admin-panel\nconfidence: 80\nmatch: { all: [ { type: title_regex, value: 'Admin' } ] }\n", true); err != nil {
		t.Fatal(err)
	}
	data := `{"schema":"asi.export/v1","hosts":[{"address":"10.0.0.9","services":[{"port":80,"protocol":"tcp","service":"http","http":{"scheme":"http","status_code":200,"title":"Shop Admin"}}]}]}`
	if rec := e.upload(e.login("edna"), map[string]string{"format": "json", "name": "lib"}, "hosts.json", []byte(data)); rec.Code != http.StatusOK {
		t.Fatalf("upload = %d: %s", rec.Code, rec.Body)
	}
	exp, err := e.inv.Export(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, h := range exp.Hosts {
		for _, s := range h.Services {
			for _, f := range s.Findings {
				ids = append(ids, f.SignatureID)
			}
		}
	}
	if strings.Join(ids, ",") != "dir-shop,db-admin" {
		t.Fatalf("findings = %v, want dir-shop and db-admin", ids)
	}
}

// REQ-WEB-053
func TestHostEntryLoadNeedsInventoryRead(t *testing.T) {
	e := newLeakEnv(t)
	e.addRole(t, "readcreate", auth.PermInventoryRead, auth.PermInventoryCreate)
	e.addRole(t, "entryeditor", auth.PermInventoryRead, auth.PermInventoryCreate, auth.PermInventoryEdit)
	if code, _ := e.get("creator", "/hosts/entry"); code != http.StatusOK {
		t.Errorf("empty entry form as inventory.create only = %d, want 200", code)
	}
	for _, addr := range []string{auditHost, "10.9.9.9"} {
		code, body := e.get("creator", "/hosts/entry?address="+addr)
		if code != http.StatusForbidden || strings.Contains(body, "ssh") || len(e.leaks(body)) > 0 {
			t.Errorf("GET /hosts/entry?address=%s as inventory.create only = %d, want 403 without host data", addr, code)
		}
	}
	if code, body := e.get("entryeditor", "/hosts/entry?address="+auditHost); code != http.StatusOK || !strings.Contains(body, "ssh") {
		t.Errorf("entry form of an existing host with read, create and edit = %d, want 200 with its services", code)
	}
	if code, _ := e.get("entryeditor", "/hosts/entry?address=10.9.9.9"); code != http.StatusNotFound {
		t.Errorf("entry form of a missing host with read, create and edit = %d, want 404", code)
	}
	if code, _ := e.get("readcreate", "/hosts/entry?address="+auditHost); code != http.StatusForbidden {
		t.Errorf("entry form of an existing host without inventory.edit = %d, want 403", code)
	}
}

var importToken = regexp.MustCompile(`<input type="hidden" name="token" value="([0-9a-f]{32})">`)

func (e *exchangeEnv) confirm(s session, token string) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/import/confirm", strings.NewReader(url.Values{"token": {token}, auth.CSRFFormField: {s.csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return e.serve(req, s)
}

// REQ-EXCHANGE-012
func TestDryRunThenConfirmImportsTheSameFile(t *testing.T) {
	e := newExchangeEnv(t)
	edna := e.login("edna")
	page := e.serve(httptest.NewRequest(http.MethodGet, "/import", nil), edna).Body.String()
	if !strings.Contains(page, `<input type="checkbox" name="dry_run" value="1" checked>`) {
		t.Fatalf("dry run is not checked by default:\n%s", page)
	}
	if importToken.MatchString(page) {
		t.Fatal("the import page offers a confirm button before any dry run")
	}

	rec := e.upload(edna, map[string]string{"format": "json", "name": "confirmed", "dry_run": "1"}, "hosts.json", []byte(twoHosts))
	body := rec.Body.String()
	for label, want := range map[string]string{"New hosts": "2", "New services": "1", "Changed": "0", "Invalid rows": "1"} {
		if got := figureValue(body, label); got != want {
			t.Errorf("dry run figure %q = %q, want %q", label, got, want)
		}
	}
	m := importToken.FindStringSubmatch(body)
	if rec.Code != http.StatusOK || m == nil || !strings.Contains(body, `<button class="primary" type="submit">Import 2 hosts</button>`) ||
		!strings.Contains(body, "is not an address.") || !strings.Contains(body, `name="dry_run" value="1" checked`) {
		t.Fatalf("dry run = %d without a confirm button:\n%s", rec.Code, body)
	}
	if e.runs() != 0 {
		t.Fatal("the dry run recorded a run")
	}

	if err := e.svc.CreateUser(context.Background(), auth.Actor{Username: "test"}, "erik", "erik-password-123", auth.RoleEditor); err != nil {
		t.Fatal(err)
	}
	erik := e.login("erik")
	if rec := e.confirm(erik, m[1]); rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), "started by another user") {
		t.Fatalf("confirm with another user's token = %d\n%s", rec.Code, rec.Body.String())
	}
	if rec := e.confirm(edna, strings.Repeat("0", 32)); rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), "Upload the file again.") {
		t.Fatalf("confirm with an unknown token = %d", rec.Code)
	}
	if e.runs() != 0 {
		t.Fatal("a rejected confirm recorded a run")
	}

	rec = e.confirm(edna, m[1])
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Imported 2 hosts and 1 service as run <code>confirmed</code>") || importToken.MatchString(rec.Body.String()) {
		t.Fatalf("confirm = %d\n%s", rec.Code, rec.Body.String())
	}
	if run, err := e.inv.RunByName(context.Background(), "confirmed"); err != nil || run.Source != inventory.SourceImport || e.runs() != 1 {
		t.Fatalf("run after confirm = %+v (%v), %d runs", run, err, e.runs())
	}
	if rec := e.confirm(edna, m[1]); rec.Code != http.StatusGone || e.runs() != 1 {
		t.Fatalf("a token used twice = %d, %d runs", rec.Code, e.runs())
	}
	vera := e.login("vera")
	if rec := e.confirm(vera, m[1]); rec.Code != http.StatusForbidden {
		t.Fatalf("confirm without the import permission = %d", rec.Code)
	}

	rec = e.upload(edna, map[string]string{"format": "json", "dry_run": "1"}, "bad.json", []byte(`{"schema":"asi.export/v1","hosts":[{"address":"x"}]}`))
	if importToken.MatchString(rec.Body.String()) {
		t.Fatal("a dry run with no valid row offers a confirm button")
	}
}

func TestExportRunIsPickedFromList(t *testing.T) {
	e := newExchangeEnv(t)
	edna, olga := e.login("edna"), e.login("olga")
	for _, name := range []string{"seed", "second"} {
		if rec := e.upload(edna, map[string]string{"name": name}, "hosts.json", []byte(twoHosts)); rec.Code != http.StatusOK {
			t.Fatalf("upload %s = %d", name, rec.Code)
		}
	}
	body := e.serve(httptest.NewRequest(http.MethodGet, "/export", nil), olga).Body.String()
	want := `<select name="run"><option value="">Latest</option><option value="second">second</option><option value="seed">seed</option></select>`
	if !strings.Contains(body, want) || strings.Contains(body, `<input type="text" name="run"`) {
		t.Fatalf("export page lacks the run select %s\n%s", want, body)
	}
	body = e.serve(httptest.NewRequest(http.MethodGet, "/export?run=seed", nil), olga).Body.String()
	if !strings.Contains(body, `<option value="seed" selected>seed</option>`) || !strings.Contains(body, "as of run <code>seed</code>") {
		t.Fatalf("export page for run seed\n%s", body)
	}
	rec := e.serve(httptest.NewRequest(http.MethodGet, "/export?run=nope", nil), olga)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `<option value="second">second</option>`) {
		t.Fatalf("unknown run = %d\n%s", rec.Code, rec.Body.String())
	}
}
