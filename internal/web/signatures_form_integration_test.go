//go:build integration

package web

import (
	"bytes"
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/detect"
	"asi/internal/inventory"
	"asi/internal/probe"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

// REQ-SIGNATURES-023 REQ-SIGNATURES-024
func TestGuidedSignatureFormEndToEnd(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DatabaseURL(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	keys, err := store.NewKeyring(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(st, auth.Config{})
	if err := svc.CreateUser(ctx, auth.Actor{Username: "test", Addr: "local"}, "eddie", "eddie-password-123", auth.RoleEditor); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	sess, err := svc.Login(ctx, "eddie", "eddie-password-123", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	cookie := &http.Cookie{Name: auth.SessionCookieName, Value: sess.Token}
	inv := inventory.New(st, keys)
	run, err := inv.CreateRun(ctx, inventory.RunSpec{Name: "r1", Settings: inventory.RunSettings{Targets: []string{"10.0.0.5"}, Ports: []int{80}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.RecordGroup(ctx, run.ID, inventory.GroupResult{Index: 0, Addresses: []string{"10.0.0.5"}, Hosts: []inventory.HostResult{{
		Address: "10.0.0.5", Services: []inventory.ServiceResult{{Port: 80, Protocol: "tcp", State: "open", Service: "http",
			HTTP: &probe.HTTP{Scheme: "http", URL: "http://10.0.0.5/", StatusCode: 200, Title: "Welcome",
				Headers: map[string]string{"server": "nginx/1.27.5"}}}},
	}}}); err != nil {
		t.Fatalf("RecordGroup: %v", err)
	}
	h, err := New(Deps{Store: st, Keyring: keys, Auth: svc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	post := func(path string, v url.Values) (int, string, string) {
		t.Helper()
		v.Set(auth.CSRFFormField, sess.CSRFToken)
		rec := do(h, http.MethodPost, path, v, cookie)
		return rec.Code, rec.Header().Get("Location"), rec.Body.String()
	}
	form := func() url.Values {
		return url.Values{"mode": {"form"}, "f_name": {"Nginx web server"}, "f_kind": {"technology"}, "f_category": {"web-server"},
			"f_confidence": {"85"}, "f_group": {"any"}, "c_matcher": {"header", "status"}, "c_name": {"Server", ""},
			"c_value": {"nginx", "200"}, "f_version_from": {"header"}, "f_version_name": {"Server"}, "f_version": {`nginx/([0-9.]+)`},
			"enabled": {"1"}, "address": {"10.0.0.5"}, "port": {"80"}, "protocol": {"tcp"}}
	}

	_, _, preview := post("/signatures/form", form())
	shown := generatedYAML(t, preview)
	code, loc, body := post("/signatures", form())
	if code != http.StatusSeeOther || loc != "/signatures?done=created&id=nginx-web-server" {
		t.Fatalf("create from the form = %d %q\n%s", code, loc, body)
	}
	lib := detect.NewLibrary(st, keys, "")
	stored, err := lib.Get(ctx, "nginx-web-server")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Source != shown {
		t.Fatalf("stored source differs from the YAML shown beside the form:\n%s\nvs\n%s", stored.Source, shown)
	}
	want, err := detect.ParseOne([]byte(shown))
	if err != nil {
		t.Fatal(err)
	}
	got, err := detect.ParseOne([]byte(stored.Source))
	if err != nil || got.Name != want.Name || len(got.Any) != 2 || got.Any[0].Name != "server" || got.Any[1].Value != "200" ||
		got.Version == nil || got.Version.Group != 1 || got.Category != "web-server" || got.Confidence != 85 || !stored.Enabled {
		t.Fatalf("stored signature = %+v, %v", got, err)
	}

	rec := do(h, http.MethodGet, "/signatures/nginx-web-server", nil, cookie)
	page := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(page, `aria-current="page">Form</a>`) || !strings.Contains(page, `name="f_name" value="Nginx web server"`) ||
		!strings.Contains(page, `<input type="hidden" name="f_id" value="nginx-web-server">`) || generatedYAML(t, page) != stored.Source {
		t.Fatalf("a form-made signature does not open in the form:\n%s", page)
	}
	v := form()
	v.Set("f_name", "Nginx")
	v.Set("f_id", "nginx-web-server")
	if code, loc, body := post("/signatures/nginx-web-server", v); code != http.StatusSeeOther || !strings.Contains(loc, "done=saved") {
		t.Fatalf("update from the form = %d %q\n%s", code, loc, body)
	}
	if s, _ := lib.Get(ctx, "nginx-web-server"); !strings.Contains(s.Source, "name: Nginx\n") {
		t.Fatalf("update did not store the form YAML:\n%s", s.Source)
	}

	code, _, body = post("/signatures/test", form())
	if code != http.StatusOK || !strings.Contains(body, "Matches 10.0.0.5 80/tcp, version 1.27.5.") || !strings.Contains(body, `name="f_name" value="Nginx web server"`) {
		t.Fatalf("test from the form = %d\n%s", code, body)
	}
	v = form()
	v.Set("since", "30d")
	code, loc, _ = post("/signatures/hunt", v)
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/signatures/hunts/") {
		t.Fatalf("hunt from the form = %d %q", code, loc)
	}
	hunt := do(h, http.MethodGet, loc, nil, cookie).Body.String()
	if !strings.Contains(hunt, `<td class="addr">10.0.0.5</td>`) || !strings.Contains(hunt, "<code>1.27.5</code>") ||
		!strings.Contains(html.UnescapeString(hunt), shown) {
		t.Fatalf("hunt did not use the generated YAML:\n%s", hunt)
	}

	both := "- id: mixed\n  name: Mixed\n  kind: custom\n  confidence: 50\n  match:\n    all: [{type: status, value: 200}]\n    any: [{type: title_regex, value: Welcome}]\n"
	if code, _, body := post("/signatures", url.Values{"source": {both}, "enabled": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("create YAML = %d\n%s", code, body)
	}
	page = do(h, http.MethodGet, "/signatures/mixed", nil, cookie).Body.String()
	if !strings.Contains(page, `aria-current="page">Edit as YAML</a>`) || !strings.Contains(page, "The form cannot show this signature") ||
		!strings.Contains(page, `<textarea name="source" rows="16" required>`) || strings.Contains(page, `name="mode"`) {
		t.Fatalf("an unrepresentable signature does not open on the YAML tab with a note:\n%s", page)
	}
	if regexp.MustCompile(`style\s*=`).MatchString(page) {
		t.Fatal("inline style on the signature page")
	}
}
