package detect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"asi/internal/probe"
)

type fakeFetcher struct {
	responses map[string]*probe.Response
	calls     []string
}

func (f *fakeFetcher) Fetch(_ context.Context, path string) (*probe.Response, error) {
	f.calls = append(f.calls, path)
	if r, ok := f.responses[path]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("no response for %s", path)
}

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mustParse(t *testing.T, src string) []Signature {
	t.Helper()
	sigs, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return sigs
}

func TestLoadLabSignatures(t *testing.T) {
	set, err := LoadDir("../../lab/signatures")
	if err != nil {
		t.Fatalf("LoadDir(lab/signatures): %v", err)
	}
	var ids []string
	for _, s := range set.Signatures {
		ids = append(ids, s.ID)
	}
	want := []string{"wordpress-generator", "drupal-x-generator", "netcam", "admin-panel-login", "php-session-cookie", "staging-environment", "debug-token-header"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("ids = %v, want %v", ids, want)
	}
	admin := set.Signatures[3]
	if admin.Method != "GET" || admin.Path != "/admin/login" || admin.Kind != "admin-panel" || admin.Confidence != 80 || len(admin.All) != 2 {
		t.Errorf("admin-panel-login = %+v", admin)
	}
}

func TestLoadDirReadsEveryYAMLFile(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"a.yaml":     "- {id: a, name: A, kind: custom, confidence: 10, match: {all: [{type: status, value: 200}]}}\n",
		"b.yaml":     "- {id: b, name: B, kind: custom, confidence: 20, match: {any: [{type: title_regex, value: x}]}}\n- {id: c, name: C, kind: iot, confidence: 30, match: {all: [{type: favicon_mmh3, value: -5}]}}\n",
		"empty.yaml": "# nothing here\n",
		"notes.txt":  "not yaml: [",
		"x.yml":      "- {id: d, name: D, kind: custom, confidence: 1, match: {all: [{type: status, value: 1}]}}\n",
	})
	set, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range set.Signatures {
		ids = append(ids, s.ID)
	}
	if !reflect.DeepEqual(ids, []string{"a", "b", "c"}) {
		t.Errorf("ids = %v", ids)
	}
	if _, err := LoadDir(writeFiles(t, map[string]string{"bad.yaml": "id: not-a-list\n"})); err == nil {
		t.Error("a file that is not a YAML list was accepted")
	}
}

func TestLoadRejectsUnsafeSignatures(t *testing.T) {
	const head = "- id: s\n  name: S\n  kind: custom\n  confidence: 50\n"
	const match = "  match: {all: [{type: status, value: 200}]}\n"
	extraPaths := ""
	for i := 1; i <= 6; i++ {
		extraPaths += fmt.Sprintf("- {id: p%d, name: P, kind: custom, confidence: 1, request: {method: GET, path: /p%d}, match: {all: [{type: status, value: 200}]}}\n", i, i)
	}
	cases := []struct {
		name  string
		files map[string]string
		rule  string
	}{
		{"method POST", map[string]string{"a.yaml": head + "  request: {method: POST, path: /x}\n" + match}, RuleMethod},
		{"method PUT", map[string]string{"a.yaml": head + "  request: {method: PUT, path: /x}\n" + match}, RuleMethod},
		{"method lower-case get", map[string]string{"a.yaml": head + "  request: {method: get, path: /x}\n" + match}, RuleMethod},
		{"request body", map[string]string{"a.yaml": head + "  request: {method: GET, path: /x, body: 'a=1'}\n" + match}, RuleBody},
		{"request headers", map[string]string{"a.yaml": head + "  request: {method: GET, path: /x, headers: {X-A: b}}\n" + match}, RuleHeaders},
		{"request credentials", map[string]string{"a.yaml": head + "  request: {method: GET, path: /x, password: hunter2}\n" + match}, RuleCredentials},
		{"path with query", map[string]string{"a.yaml": head + "  request: {method: GET, path: '/x?a=1'}\n" + match}, RulePath},
		{"path with fragment", map[string]string{"a.yaml": head + "  request: {method: GET, path: '/x#y'}\n" + match}, RulePath},
		{"relative path", map[string]string{"a.yaml": head + "  request: {method: GET, path: admin}\n" + match}, RulePath},
		{"network-path reference", map[string]string{"a.yaml": head + "  request: {method: GET, path: //evil.example/}\n" + match}, RulePath},
		{"dot-dot path parameter", map[string]string{"a.yaml": head + "  request: {method: GET, path: '/..;/manager/html'}\n" + match}, RulePath},
		{"encoded dot-dot path parameter", map[string]string{"a.yaml": head + "  request: {method: GET, path: '/app/%2e%2e;x=1/etc'}\n" + match}, RulePath},
		{"invalid body regex", map[string]string{"a.yaml": head + "  match: {all: [{type: body_regex, value: '(a'}]}\n"}, RuleRegex},
		{"invalid header regex", map[string]string{"a.yaml": head + "  match: {any: [{type: header, name: Server, value: '[a'}]}\n"}, RuleRegex},
		{"invalid cookie regex", map[string]string{"a.yaml": head + "  match: {all: [{type: cookie, name: '*x'}]}\n"}, RuleRegex},
		{"non-RE2 lookahead", map[string]string{"a.yaml": head + "  match: {all: [{type: title_regex, value: 'a(?=b)'}]}\n"}, RuleRegex},
		{"version group out of range", map[string]string{"a.yaml": head + match + "  version: {type: body_regex, value: 'v([0-9]+)', group: 2}\n"}, RuleRegex},
		{"duplicate id in one file", map[string]string{"a.yaml": head + match + head + match}, RuleDuplicateID},
		{"duplicate id across files", map[string]string{"a.yaml": head + match, "b.yaml": head + match}, RuleDuplicateID},
		{"six extra request paths", map[string]string{"a.yaml": extraPaths}, RuleExtraRequests},
		{"bad id", map[string]string{"a.yaml": "- {id: Bad_ID, name: S, kind: custom, confidence: 1, match: {all: [{type: status, value: 200}]}}\n"}, RuleSchema},
		{"unknown kind", map[string]string{"a.yaml": "- {id: s, name: S, kind: exploit, confidence: 1, match: {all: [{type: status, value: 200}]}}\n"}, RuleSchema},
		{"confidence above 100", map[string]string{"a.yaml": "- {id: s, name: S, kind: custom, confidence: 101, match: {all: [{type: status, value: 200}]}}\n"}, RuleSchema},
		{"no matchers", map[string]string{"a.yaml": head + "  match: {}\n"}, RuleSchema},
		{"unknown matcher type", map[string]string{"a.yaml": head + "  match: {all: [{type: port, value: 22}]}\n"}, RuleSchema},
		{"non-integer status", map[string]string{"a.yaml": head + "  match: {all: [{type: status, value: ok}]}\n"}, RuleSchema},
		{"bad favicon sha256", map[string]string{"a.yaml": head + "  match: {all: [{type: favicon_sha256, value: abc}]}\n"}, RuleSchema},
		{"bad favicon mmh3", map[string]string{"a.yaml": head + "  match: {all: [{type: favicon_mmh3, value: 99999999999}]}\n"}, RuleSchema},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadDir(writeFiles(t, tc.files))
			var re *RuleError
			if !errors.As(err, &re) {
				t.Fatalf("err = %v, want a RuleError", err)
			}
			if re.Rule != tc.rule || !strings.Contains(err.Error(), tc.rule) {
				t.Errorf("err = %v, want rule %q", err, tc.rule)
			}
		})
	}
}

func TestMatchers(t *testing.T) {
	icon := []byte("icon-bytes")
	sum := sha256.Sum256(icon)
	iconSHA := hex.EncodeToString(sum[:])
	iconMMH3 := probe.FaviconHash(icon)
	root := &probe.Response{
		StatusCode: 200,
		Title:      "Router NETCAM [staging]",
		Headers:    map[string]string{"server": "nginx/1.27.5", "x-generator": "Drupal 10 (https://www.drupal.org)"},
		Cookies:    []probe.Cookie{{Name: "PHPSESSID"}, {Name: "lang"}},
		Body:       []byte(`<html><p>Firmware V2.3.1</p><input type="password"></html>`),
	}
	h := &probe.HTTP{FaviconSHA256: iconSHA, FaviconMMH3: iconMMH3}
	cases := []struct {
		name    string
		match   string
		version string
		want    bool
		wantVer string
	}{
		{"status hit", "all: [{type: status, value: 200}]", "", true, ""},
		{"status miss", "all: [{type: status, value: 404}]", "", false, ""},
		{"header name case-insensitive", "all: [{type: header, name: X-GENERATOR, value: '^Drupal'}]", "", true, ""},
		{"header value miss", "all: [{type: header, name: Server, value: '^Apache'}]", "", false, ""},
		{"header absent", "all: [{type: header, name: X-Missing, value: ''}]", "", false, ""},
		{"cookie name regex", "all: [{type: cookie, name: '^PHPSESS'}]", "", true, ""},
		{"cookie miss", "all: [{type: cookie, name: '^JSESSIONID$'}]", "", false, ""},
		{"title regex", "all: [{type: title_regex, value: '(?i)\\[staging\\]'}]", "", true, ""},
		{"title miss", "all: [{type: title_regex, value: 'Login'}]", "", false, ""},
		{"body regex", "all: [{type: body_regex, value: 'type=\"password\"'}]", "", true, ""},
		{"body miss", "all: [{type: body_regex, value: 'wp-content'}]", "", false, ""},
		{"favicon sha256", "all: [{type: favicon_sha256, value: " + strings.ToUpper(iconSHA) + "}]", "", true, ""},
		{"favicon sha256 miss", "all: [{type: favicon_sha256, value: " + strings.Repeat("0", 64) + "}]", "", false, ""},
		{"favicon mmh3", "all: [{type: favicon_mmh3, value: " + strconv.Itoa(int(iconMMH3)) + "}]", "", true, ""},
		{"favicon mmh3 miss", "all: [{type: favicon_mmh3, value: 1}]", "", false, ""},
		{"all needs every matcher", "all: [{type: status, value: 200}, {type: title_regex, value: nope}]", "", false, ""},
		{"any needs one matcher", "any: [{type: status, value: 500}, {type: title_regex, value: NETCAM}]", "", true, ""},
		{"any with none", "any: [{type: status, value: 500}, {type: title_regex, value: nope}]", "", false, ""},
		{"all and any both hold", "all: [{type: status, value: 200}]\n    any: [{type: cookie, name: lang}]", "", true, ""},
		{"all holds, any fails", "all: [{type: status, value: 200}]\n    any: [{type: cookie, name: nope}]", "", false, ""},
		{"version from body group", "all: [{type: status, value: 200}]", "{type: body_regex, value: 'Firmware V([0-9.]+)', group: 1}", true, "2.3.1"},
		{"version from header group", "all: [{type: status, value: 200}]", "{type: header, name: X-Generator, value: '^Drupal ([0-9]+)', group: 1}", true, "10"},
		{"version from title whole match", "all: [{type: status, value: 200}]", "{type: title_regex, value: 'NETCAM'}", true, "NETCAM"},
		{"version not visible", "all: [{type: status, value: 200}]", "{type: body_regex, value: 'Build ([0-9]+)', group: 1}", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "- id: m\n  name: M\n  kind: custom\n  confidence: 50\n  match:\n    " + tc.match + "\n"
			if tc.version != "" {
				src += "  version: " + tc.version + "\n"
			}
			set := &Set{Signatures: mustParse(t, src)}
			res := set.detect(context.Background(), &fakeFetcher{responses: map[string]*probe.Response{"/": root}}, h)
			if got := len(res.Findings) == 1; got != tc.want {
				t.Fatalf("matched = %v, want %v (findings %+v)", got, tc.want, res.Findings)
			}
			if tc.want && res.Findings[0].Version != tc.wantVer {
				t.Errorf("version = %q, want %q", res.Findings[0].Version, tc.wantVer)
			}
		})
	}
	t.Run("favicon mmh3 zero without favicon", func(t *testing.T) {
		set := &Set{Signatures: mustParse(t, "- {id: m, name: M, kind: iot, confidence: 1, match: {all: [{type: favicon_mmh3, value: 0}]}}\n")}
		res := set.detect(context.Background(), &fakeFetcher{responses: map[string]*probe.Response{"/": root}}, &probe.HTTP{})
		if len(res.Findings) != 0 {
			t.Errorf("findings = %+v", res.Findings)
		}
	})
}

type recorder struct {
	mu    sync.Mutex
	paths []string
}

func (r *recorder) add(p string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, p)
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.paths...)
}

func serve(t *testing.T, h http.HandlerFunc) (*probe.Session, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			t.Errorf("unexpected method %s", r.Method)
		}
		rec.add(r.URL.Path)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	sess, err := probe.Probe(context.Background(), host, port, false, "")
	if err != nil {
		t.Fatal(err)
	}
	return sess, rec
}

func TestDetectLabSignaturesFindingsAndTechnologies(t *testing.T) {
	set, err := LoadDir("../../lab/signatures")
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("X-Debug-Token", "s3cr3t-token-value")
			w.Header().Set("Server", "nginx/1.27.5")
			fmt.Fprint(w, `<html><head><title>Campus Blog</title><meta name="generator" content="WordPress 6.4.2"></head><body><link href="/wp-content/x.css"></body></html>`)
		case "/admin/login":
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "session-secret"})
			fmt.Fprint(w, `<form><input type="password" name="p"></form>`)
		default:
			http.NotFound(w, r)
		}
	})
	res := set.Detect(context.Background(), sess)
	byID := map[string]Finding{}
	for _, f := range res.Findings {
		byID[f.SignatureID] = f
		if strings.Contains(f.Evidence, "s3cr3t") || strings.Contains(f.Evidence, "session-secret") {
			t.Errorf("evidence leaks a secret: %q", f.Evidence)
		}
		if f.Evidence == "" || len([]rune(f.Evidence)) > maxEvidenceLen {
			t.Errorf("evidence %q is empty or too long", f.Evidence)
		}
	}
	wp := byID["wordpress-generator"]
	if wp.Kind != "technology" || wp.Name != "WordPress" || wp.Version != "6.4.2" || wp.Confidence != 95 {
		t.Errorf("wordpress-generator finding = %+v", wp)
	}
	for _, id := range []string{"admin-panel-login", "php-session-cookie", "debug-token-header"} {
		if _, ok := byID[id]; !ok {
			t.Errorf("missing finding %s in %+v", id, res.Findings)
		}
	}
	if len(byID) != 4 {
		t.Errorf("findings = %+v", res.Findings)
	}
	if !strings.Contains(byID["admin-panel-login"].Evidence, "GET /admin/login") {
		t.Errorf("admin evidence = %q", byID["admin-panel-login"].Evidence)
	}
	want := []Technology{
		{Name: "WordPress", Category: "cms", Version: "6.4.2", Confidence: 95, Source: "signature:wordpress-generator"},
		{Name: "nginx", Category: "web-server", Version: "1.27.5", Confidence: 90, Source: SourceBuiltin},
	}
	if !reflect.DeepEqual(res.Technologies, want) {
		t.Errorf("technologies = %+v, want %+v", res.Technologies, want)
	}
}

func TestDetectFetchesSignaturePathsOnceAndAtMostFive(t *testing.T) {
	var src strings.Builder
	paths := []string{"/a", "/b", "/a", "/", "/c", "/d", "/b", "/e"}
	for i, p := range paths {
		fmt.Fprintf(&src, "- {id: s%d, name: S%d, kind: custom, confidence: 1, request: {method: HEAD, path: '%s'}, match: {all: [{type: status, value: 200}]}}\n", i, i, p)
	}
	sigs := mustParse(t, src.String())
	sigs = append(sigs, mustParse(t, "- {id: f, name: F, kind: custom, confidence: 1, request: {method: GET, path: /f}, match: {all: [{type: status, value: 200}]}}\n")...)
	sess, rec := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
		}
	})
	probed := len(rec.list())
	res := (&Set{Signatures: sigs}).Detect(context.Background(), sess)
	got := rec.list()[probed:]
	if !reflect.DeepEqual(got, []string{"/a", "/b", "/c", "/d", "/e"}) {
		t.Errorf("signature requests = %v", got)
	}
	var ids []string
	for _, f := range res.Findings {
		ids = append(ids, f.SignatureID)
	}
	if !reflect.DeepEqual(ids, []string{"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"}) {
		t.Errorf("findings = %v (signature beyond the cap must not match)", ids)
	}
	ok := &probe.Response{StatusCode: 200}
	f := &fakeFetcher{responses: map[string]*probe.Response{"/": ok, "/a": ok, "/b": ok, "/c": ok, "/d": ok, "/e": ok, "/f": ok}}
	(&Set{Signatures: sigs}).detect(context.Background(), f, &probe.HTTP{})
	if !reflect.DeepEqual(f.calls, []string{"/", "/a", "/b", "/c", "/d", "/e"}) {
		t.Errorf("fetches = %v, want / plus at most five extra paths", f.calls)
	}
}

func TestDetectSkipsFailedFetchWithoutRetry(t *testing.T) {
	sigs := mustParse(t, "- {id: a, name: A, kind: custom, confidence: 1, request: {method: GET, path: /gone}, match: {all: [{type: status, value: 200}]}}\n- {id: b, name: B, kind: custom, confidence: 1, request: {method: GET, path: /gone}, match: {all: [{type: status, value: 200}]}}\n")
	f := &fakeFetcher{responses: map[string]*probe.Response{"/": {StatusCode: 200, Headers: map[string]string{}}}}
	res := (&Set{Signatures: sigs}).detect(context.Background(), f, &probe.HTTP{})
	if len(res.Findings) != 0 || !reflect.DeepEqual(f.calls, []string{"/", "/gone"}) {
		t.Errorf("findings = %+v, calls = %v", res.Findings, f.calls)
	}
}

func TestBuiltin(t *testing.T) {
	cases := []struct {
		name string
		resp probe.Response
		want []Technology
	}{
		{
			name: "nginx with version",
			resp: probe.Response{Headers: map[string]string{"server": "nginx/1.27.5"}},
			want: []Technology{{Name: "nginx", Category: "web-server", Version: "1.27.5", Confidence: 90, Source: "builtin"}},
		},
		{
			name: "nginx without version",
			resp: probe.Response{Headers: map[string]string{"server": "nginx"}},
			want: []Technology{{Name: "nginx", Category: "web-server", Confidence: 90, Source: "builtin"}},
		},
		{
			name: "Apache and PHP from headers",
			resp: probe.Response{Headers: map[string]string{"server": "Apache/2.4.58 (Debian)", "x-powered-by": "PHP/8.2.12"}},
			want: []Technology{
				{Name: "Apache", Category: "web-server", Version: "2.4.58", Confidence: 90, Source: "builtin"},
				{Name: "PHP", Category: "programming-language", Version: "8.2.12", Confidence: 90, Source: "builtin"},
			},
		},
		{
			name: "Apache-Coyote is not Apache httpd",
			resp: probe.Response{Headers: map[string]string{"server": "Apache-Coyote/1.1"}},
			want: nil,
		},
		{
			name: "PHP from the Server header",
			resp: probe.Response{Headers: map[string]string{"server": "Apache/2.4.41 (Ubuntu) PHP/7.4.3"}},
			want: []Technology{
				{Name: "Apache", Category: "web-server", Version: "2.4.41", Confidence: 90, Source: "builtin"},
				{Name: "PHP", Category: "programming-language", Version: "7.4.3", Confidence: 90, Source: "builtin"},
			},
		},
		{
			name: "PHP session cookie merged with versioned header",
			resp: probe.Response{Headers: map[string]string{"x-powered-by": "PHP/7.4.3"}, Cookies: []probe.Cookie{{Name: "PHPSESSID"}}},
			want: []Technology{{Name: "PHP", Category: "programming-language", Version: "7.4.3", Confidence: 90, Source: "builtin"}},
		},
		{
			name: "PHP from cookie only",
			resp: probe.Response{Cookies: []probe.Cookie{{Name: "lang"}, {Name: "PHPSESSID"}}},
			want: []Technology{{Name: "PHP", Category: "programming-language", Confidence: 60, Source: "builtin"}},
		},
		{
			name: "WordPress from meta generator and body markers",
			resp: probe.Response{Body: []byte(`<head><META Name="Generator" content="WordPress 6.4.2"/><link rel="stylesheet" href="/wp-content/themes/x.css"></head>`)},
			want: []Technology{{Name: "WordPress", Category: "cms", Version: "6.4.2", Confidence: 95, Source: "builtin"}},
		},
		{
			name: "WordPress from body markers only",
			resp: probe.Response{Body: []byte(`<script src="/wp-includes/js/jquery.js"></script>`)},
			want: []Technology{{Name: "WordPress", Category: "cms", Confidence: 70, Source: "builtin"}},
		},
		{
			name: "WordPress from cookie and link header",
			resp: probe.Response{Headers: map[string]string{"link": `<http://blog/wp-json/>; rel="https://api.w.org/"`}, Cookies: []probe.Cookie{{Name: "wordpress_test_cookie"}}},
			want: []Technology{{Name: "WordPress", Category: "cms", Confidence: 80, Source: "builtin"}},
		},
		{
			name: "Drupal from X-Generator",
			resp: probe.Response{Headers: map[string]string{"x-generator": "Drupal 10 (https://www.drupal.org)"}},
			want: []Technology{{Name: "Drupal", Category: "cms", Version: "10", Confidence: 90, Source: "builtin"}},
		},
		{
			name: "Drupal from meta generator",
			resp: probe.Response{Body: []byte(`<meta content="Drupal 9 (https://www.drupal.org)" name="generator">`)},
			want: []Technology{{Name: "Drupal", Category: "cms", Version: "9", Confidence: 95, Source: "builtin"}},
		},
		{
			name: "Drupal from cache header and body",
			resp: probe.Response{Headers: map[string]string{"x-drupal-cache": "HIT"}, Body: []byte(`<script data-drupal-selector="drupal-settings-json"></script>`)},
			want: []Technology{{Name: "Drupal", Category: "cms", Confidence: 80, Source: "builtin"}},
		},
		{
			name: "Joomla from meta generator without version",
			resp: probe.Response{Body: []byte(`<meta name="generator" content="Joomla! - Open Source Content Management">`)},
			want: []Technology{{Name: "Joomla", Category: "cms", Confidence: 95, Source: "builtin"}},
		},
		{
			name: "Joomla from body marker",
			resp: probe.Response{Body: []byte(`<script src="/media/system/js/core.js"></script>`)},
			want: []Technology{{Name: "Joomla", Category: "cms", Confidence: 60, Source: "builtin"}},
		},
		{
			name: "plain page",
			resp: probe.Response{Headers: map[string]string{"content-type": "text/html"}, Body: []byte(`<title>Hello</title><meta name="description" content="WordPress">`)},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Builtin(&tc.resp); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Builtin = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestMergeKeepsHighestConfidence(t *testing.T) {
	got := Merge([]Technology{
		{Name: "Drupal", Category: "cms", Version: "", Confidence: 70, Source: "builtin"},
		{Name: "nginx", Category: "web-server", Confidence: 90, Source: "builtin"},
		{Name: "drupal", Category: "", Version: "10", Confidence: 90, Source: "signature:drupal-x-generator"},
		{Name: "Drupal", Category: "cms", Version: "9", Confidence: 80, Source: "builtin"},
		{Name: "nginx", Category: "web-server", Version: "1.27.5", Confidence: 90, Source: "signature:nginx"},
	})
	want := []Technology{
		{Name: "drupal", Category: "cms", Version: "10", Confidence: 90, Source: "signature:drupal-x-generator"},
		{Name: "nginx", Category: "web-server", Version: "1.27.5", Confidence: 90, Source: "builtin"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Merge = %+v, want %+v", got, want)
	}
}

// REQ-EXCHANGE-003
func TestDetectRecordedMatchesStoredResponseOnly(t *testing.T) {
	set := &Set{Signatures: mustParse(t, `
- id: shop-title
  name: Shop
  kind: technology
  confidence: 70
  match: { all: [ { type: title_regex, value: 'Shop v' } ] }
  version: { type: title_regex, value: 'Shop v([0-9.]+)', group: 1 }
- id: admin-path
  name: Admin
  kind: admin-panel
  confidence: 80
  request: { method: GET, path: /admin }
  match: { all: [ { type: status, value: 200 } ] }
`)}
	h := &probe.HTTP{StatusCode: 200, Title: "Shop v2.1", Headers: map[string]string{"server": "nginx/1.27.5"}}
	res := set.DetectRecorded(h)
	if len(res.Findings) != 1 || res.Findings[0].SignatureID != "shop-title" || res.Findings[0].Version != "2.1" {
		t.Fatalf("findings = %+v, want only shop-title (no request for /admin)", res.Findings)
	}
	names := map[string]string{}
	for _, tech := range res.Technologies {
		names[tech.Name] = tech.Version + " " + tech.Source
	}
	if names["Shop"] != "2.1 signature:shop-title" || names["nginx"] != "1.27.5 builtin" {
		t.Fatalf("technologies = %+v", res.Technologies)
	}
	var none *Set
	if got := none.DetectRecorded(h); len(got.Findings) != 0 || len(got.Technologies) != 1 {
		t.Fatalf("nil set = %+v", got)
	}
}

// REQ-SIGNATURES-001
func TestParseOneAppliesTheLoaderRules(t *testing.T) {
	const ok = "id: s\nname: S\nkind: custom\nconfidence: 50\nmatch: {all: [{type: status, value: 200}]}\n"
	for _, src := range []string{ok, "- " + strings.ReplaceAll(strings.TrimSuffix(ok, "\n"), "\n", "\n  ") + "\n"} {
		s, err := ParseOne([]byte(src))
		if err != nil || s.ID != "s" || s.Path != "/" {
			t.Fatalf("ParseOne(%q) = %+v, %v", src, s, err)
		}
	}
	cases := map[string]string{
		"id: s\nname: S\nkind: custom\nconfidence: 50\nrequest: {method: POST, path: /x}\nmatch: {all: [{type: status, value: 200}]}\n":    RuleMethod,
		"id: s\nname: S\nkind: custom\nconfidence: 50\nrequest: {path: /x, headers: {a: b}}\nmatch: {all: [{type: status, value: 200}]}\n": RuleHeaders,
		ok + "extra: 1\n":             RuleSchema,
		"- " + "{id: a}\n- {id: b}\n": RuleSchema,
		"id: [":                       RuleSchema,
		"":                            RuleSchema,
	}
	for src, rule := range cases {
		_, err := ParseOne([]byte(src))
		var re *RuleError
		if !errors.As(err, &re) || re.Rule != rule {
			t.Errorf("ParseOne(%q) = %v, want rule %q", src, err, rule)
		}
	}
}

// REQ-SIGNATURES-004
func TestSplitAndJoinSourcesRoundTrip(t *testing.T) {
	data := []byte("# lab file\n- id: a\n  name: A # the a\n  kind: custom\n  confidence: 1\n  match: {all: [{type: status, value: 200}]}\n- {id: b, name: B, kind: iot, confidence: 2, match: {any: [{type: title_regex, value: x}]}}\n")
	sigs, srcs, err := SplitSources(data)
	if err != nil || len(sigs) != 2 || len(srcs) != 2 {
		t.Fatalf("SplitSources = %v, %d sources, %v", sigs, len(srcs), err)
	}
	if one, err := ParseOne(srcs[1]); err != nil || one.ID != "b" {
		t.Fatalf("ParseOne(source b) = %+v, %v", one, err)
	}
	joined, err := JoinSources(srcs)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(joined)
	if err != nil || len(again) != 2 || again[0].ID != "a" || again[1].ID != "b" || again[1].Kind != "iot" {
		t.Fatalf("Parse(JoinSources) = %+v, %v\n%s", again, err, joined)
	}
	if empty, err := JoinSources(nil); err != nil || string(empty) != "[]\n" {
		t.Fatalf("JoinSources(nil) = %q, %v", empty, err)
	}
	if _, _, err := SplitSources([]byte("- {id: a, name: A, kind: custom, confidence: 1, request: {method: DELETE}, match: {all: [{type: status, value: 200}]}}\n")); !strings.Contains(fmt.Sprint(err), RuleMethod) {
		t.Fatalf("SplitSources unsafe = %v, want %q", err, RuleMethod)
	}
}

// REQ-SIGNATURES-003
func TestCombineRejectsClashesAndTooManyPaths(t *testing.T) {
	file := &Set{Signatures: mustParse(t, "- {id: a, name: A, kind: custom, confidence: 1, request: {path: /a}, match: {all: [{type: status, value: 200}]}}\n")}
	extra := mustParse(t, "- {id: b, name: B, kind: custom, confidence: 1, match: {all: [{type: status, value: 200}]}}\n")
	set, err := Combine(file, extra)
	if err != nil || len(set.Signatures) != 2 {
		t.Fatalf("Combine = %+v, %v", set, err)
	}
	if _, err := Combine(file, mustParse(t, "- {id: a, name: A2, kind: custom, confidence: 1, match: {all: [{type: status, value: 200}]}}\n")); !strings.Contains(fmt.Sprint(err), RuleDuplicateID) {
		t.Fatalf("Combine clash = %v, want %q", err, RuleDuplicateID)
	}
	var paths string
	for i := 1; i <= 5; i++ {
		paths += fmt.Sprintf("- {id: p%d, name: P, kind: custom, confidence: 1, request: {path: /p%d}, match: {all: [{type: status, value: 200}]}}\n", i, i)
	}
	if _, err := Combine(file, mustParse(t, paths)); !strings.Contains(fmt.Sprint(err), RuleExtraRequests) {
		t.Fatalf("Combine six paths = %v, want %q", err, RuleExtraRequests)
	}
}

// REQ-SIGNATURES-002
func TestEvaluateStoredUsesOnlyTheStoredResponse(t *testing.T) {
	h := &probe.HTTP{StatusCode: 200, Title: "Grafana", Headers: map[string]string{"server": "nginx/1.27.5"}, Cookies: []probe.Cookie{{Name: "grafana_session"}}}
	sig, err := ParseOne([]byte("id: g\nname: Grafana\nkind: technology\nconfidence: 90\nmatch:\n  all: [{type: title_regex, value: Grafana}, {type: cookie, name: '^grafana_'}]\nversion: {type: header, name: Server, value: 'nginx/([0-9.]+)', group: 1}\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := sig.EvaluateStored(h)
	if !e.Matched || e.Version != "1.27.5" || len(e.Evidence) != 2 {
		t.Fatalf("EvaluateStored = %+v, want a match with version 1.27.5", e)
	}
	miss, _ := ParseOne([]byte("id: m\nname: M\nkind: custom\nconfidence: 1\nmatch: {all: [{type: status, value: 404}]}\n"))
	if e := miss.EvaluateStored(h); e.Matched || e.Reason == "" {
		t.Fatalf("non-matching = %+v", e)
	}
	other, _ := ParseOne([]byte("id: o\nname: O\nkind: custom\nconfidence: 1\nrequest: {path: /admin}\nmatch: {all: [{type: status, value: 200}]}\n"))
	if e := other.EvaluateStored(h); e.Matched || !strings.Contains(e.Reason, "/admin") {
		t.Fatalf("other path = %+v, want no match naming /admin", e)
	}
	if e := sig.EvaluateStored(nil); e.Matched || e.Reason == "" {
		t.Fatalf("no HTTP = %+v", e)
	}
}

// REQ-SIGNATURES-006
func TestEvaluateHistoryUsesTheStoredBody(t *testing.T) {
	h := &probe.HTTP{StatusCode: 200, Title: "Jenkins", Headers: map[string]string{}}
	sig, err := ParseOne([]byte("id: j\nname: Jenkins\nkind: technology\nconfidence: 90\nmatch:\n  all: [{type: title_regex, value: Jenkins}, {type: body_regex, value: 'Jenkins ver'}]\nversion: {type: body_regex, value: 'ver\\. ([0-9.]+)', group: 1}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := sig.EvaluateHistory(h, []byte("<p>Jenkins ver. 2.401</p>")); !ok || !e.Matched || e.Version != "2.401" {
		t.Fatalf("with body = %+v, %t; want a match with version 2.401", e, ok)
	}
	if e, ok := sig.EvaluateHistory(h, []byte{}); !ok || e.Matched {
		t.Fatalf("empty body = %+v, %t; want evaluable without a match", e, ok)
	}
	if e, ok := sig.EvaluateHistory(h, nil); ok || e.Matched {
		t.Fatalf("no stored body = %+v, %t; want not evaluable", e, ok)
	}
	title, _ := ParseOne([]byte("id: t\nname: T\nkind: custom\nconfidence: 1\nmatch: {all: [{type: title_regex, value: Jenkins}]}\n"))
	if e, ok := title.EvaluateHistory(h, nil); !ok || !e.Matched {
		t.Fatalf("title only without body = %+v, %t; want a match", e, ok)
	}
	other, _ := ParseOne([]byte("id: o\nname: O\nkind: custom\nconfidence: 1\nrequest: {path: /admin}\nmatch: {all: [{type: status, value: 200}]}\n"))
	if e, ok := other.EvaluateHistory(h, []byte("x")); ok || e.Matched || !strings.Contains(e.Reason, "/admin") {
		t.Fatalf("other path = %+v, %t; want not evaluable naming /admin", e, ok)
	}
}

func TestSignaturePathIsNormalised(t *testing.T) {
	for in, want := range map[string]string{"/a//b": "/a/b", "/admin/": "/admin/", "/": "/", "/app;jsessionid=1/x": "/app;jsessionid=1/x"} {
		src := "id: p\nname: P\nkind: custom\nconfidence: 50\nrequest: {path: '" + in + "'}\nmatch: {all: [{type: status, value: 200}]}\n"
		sig, err := ParseOne([]byte(src))
		if err != nil || sig.Path != want {
			t.Errorf("path %q = %q, %v; want %q", in, sig.Path, err, want)
		}
	}
}

func TestMergeKeepsOneEntryPerSignatureSource(t *testing.T) {
	got := Merge([]Technology{
		{Name: "Gitea", Category: "code-hosting", Version: "1.21.4", Confidence: 95, Source: "signature:builtin-gitea"},
		{Name: "Gitea", Category: "code-hosting", Confidence: 90, Source: "signature:eval-gitea"},
		{Name: "gitea", Category: "code-hosting", Version: "1.21", Confidence: 80, Source: "signature:builtin-gitea-footer"},
		{Name: "Gitea", Category: "code-hosting", Version: "1.21.4", Confidence: 70, Source: "signature:eval-gitea"},
		{Name: "Gitea", Confidence: 60, Source: "signature:other-gitea"},
		{Name: "WordPress", Category: "cms", Version: "6.4.2", Confidence: 95, Source: "signature:wordpress-generator"},
		{Name: "WordPress", Category: "cms", Confidence: 70, Source: SourceBuiltin},
	})
	want := []Technology{
		{Name: "Gitea", Category: "code-hosting", Version: "1.21.4", Confidence: 95, Source: "signature:builtin-gitea"},
		{Name: "Gitea", Category: "code-hosting", Version: "1.21.4", Confidence: 90, Source: "signature:eval-gitea"},
		{Name: "Gitea", Confidence: 60, Source: "signature:other-gitea"},
		{Name: "WordPress", Category: "cms", Version: "6.4.2", Confidence: 95, Source: "signature:wordpress-generator"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Merge = %+v, want %+v", got, want)
	}
}

// REQ-SIGNATURES-027
func TestMergeFindingsByKindNameAndVersion(t *testing.T) {
	in := []Finding{
		{SignatureID: "a", Kind: KindStaging, Name: "Staging", Confidence: 60, Evidence: "title"},
		{SignatureID: "v1", Kind: "technology", Name: "Gitea", Version: "1.21.4", Confidence: 95},
		{SignatureID: "b", Kind: KindStaging, Name: "Staging", Confidence: 75, Evidence: "header"},
		{SignatureID: "v0", Kind: "technology", Name: "Gitea", Confidence: 90},
	}
	once := MergeFindings(in)
	want := []Finding{
		{SignatureID: "b", Kind: KindStaging, Name: "Staging", Confidence: 75, Evidence: "header; also matched by a"},
		{SignatureID: "v1", Kind: "technology", Name: "Gitea", Version: "1.21.4", Confidence: 95},
		{SignatureID: "v0", Kind: "technology", Name: "Gitea", Confidence: 90},
	}
	if !reflect.DeepEqual(once, want) {
		t.Fatalf("MergeFindings = %+v, want %+v", once, want)
	}
	if again := MergeFindings(once); !reflect.DeepEqual(again, want) {
		t.Errorf("merging again = %+v, want it unchanged", again)
	}
	more := MergeFindings(append(once, Finding{SignatureID: "c", Kind: KindStaging, Name: "Staging", Confidence: 80, Evidence: "hostname"}))
	if more[0].SignatureID != "c" || more[0].Evidence != "hostname; also matched by b, a" {
		t.Errorf("merge with a stronger finding = %+v, want c keeping the ids b and a", more[0])
	}
}

// REQ-SIGNATURES-027: one admin panel and one finding per notable header on a lab service, whatever each signature
// calls it.
func TestMergeFindingsAcrossNamesOnLabServices(t *testing.T) {
	cases := []struct {
		service, kind, header string
		ids                   []string
	}{
		{"admin", KindAdminPanel, "", []string{"admin-panel-login", "builtin-admin-login"}},
		{"staging", KindInterestingHeader, "x-debug-token", []string{"debug-token-header", "builtin-header-x-debug-token"}},
	}
	for _, c := range cases {
		t.Run(c.service, func(t *testing.T) {
			var got []Finding
			for _, f := range detectLabServiceWithLabSignatures(t, c.service).Findings {
				if f.Kind == c.kind && (c.header == "" || strings.Contains(strings.ToLower(f.Evidence), c.header)) {
					got = append(got, f)
				}
			}
			if len(got) != 1 {
				t.Fatalf("%s findings = %+v, want one", c.kind, got)
			}
			for _, id := range c.ids {
				if got[0].SignatureID != id && !strings.Contains(got[0].Evidence, id) {
					t.Errorf("merged %s finding %+v does not name %s", c.kind, got[0], id)
				}
			}
		})
	}
}

// REQ-SIGNATURES-027: a user signature stays the visible finding when a built-in one matches the same trait more
// strongly; the merged finding keeps the higher confidence.
func TestMergeFindingsPrefersUserSignatures(t *testing.T) {
	got := MergeFindings([]Finding{
		{SignatureID: "builtin-header-x-debug-token", Kind: KindInterestingHeader, Name: "Debug header exposed", Confidence: 80, Evidence: "X-Debug-Token: <token redacted, 6 characters>"},
		{SignatureID: "debug-token-header", Kind: KindInterestingHeader, Name: "Debug token header exposed", Confidence: 70, Evidence: `GET /: header x-debug-token matches ".+"`},
	})
	want := []Finding{{SignatureID: "debug-token-header", Kind: KindInterestingHeader, Name: "Debug token header exposed", Confidence: 80,
		Evidence: `GET /: header x-debug-token matches ".+"; also matched by builtin-header-x-debug-token`}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MergeFindings = %+v, want %+v", got, want)
	}
}
