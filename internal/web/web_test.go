package web

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"asi/internal/auth"
	"asi/internal/diff"
	"asi/internal/inventory"
)

type fakeAuth struct {
	*auth.Service
	passwords map[string]string
	roles     map[string]auth.Principal
	sessions  map[string]auth.Principal
	loggedOut []string
}

func newFakeAuth() *fakeAuth {
	return &fakeAuth{
		Service:   auth.NewService(nil, auth.Config{}),
		passwords: map[string]string{"alice": "alice-password-1", "victor": "victor-password-1"},
		roles: map[string]auth.Principal{
			"alice":  {Username: "alice", Role: auth.RoleAdmin, Permissions: auth.AllPermissions},
			"victor": {Username: "victor", Role: auth.RoleViewer, Permissions: []auth.Permission{auth.PermInventoryRead}},
		},
		sessions: map[string]auth.Principal{},
	}
}

func (f *fakeAuth) Login(_ context.Context, username, password, _ string) (auth.Session, error) {
	if username == "limited" {
		return auth.Session{}, auth.ErrRateLimited
	}
	if want, ok := f.passwords[username]; !ok || want != password {
		return auth.Session{}, auth.ErrInvalidCredentials
	}
	sess := auth.Session{Token: "tok-" + username, CSRFToken: "csrf-" + username, Username: username}
	p := f.roles[username]
	p.CSRFToken = sess.CSRFToken
	f.sessions[sess.Token] = p
	return sess, nil
}

func (f *fakeAuth) Logout(_ context.Context, token, _ string) error {
	delete(f.sessions, token)
	f.loggedOut = append(f.loggedOut, token)
	return nil
}

func (f *fakeAuth) LookupSession(_ context.Context, token string) (auth.Principal, error) {
	p, ok := f.sessions[token]
	if !ok {
		return auth.Principal{}, auth.ErrNoSession
	}
	return p, nil
}

func (f *fakeAuth) session(t *testing.T, username string) *http.Cookie {
	t.Helper()
	sess, err := f.Login(context.Background(), username, f.passwords[username], "")
	if err != nil {
		t.Fatalf("fake login %s: %v", username, err)
	}
	return &http.Cookie{Name: auth.SessionCookieName, Value: sess.Token}
}

func newTestRouter(t *testing.T, extra ...Feature) (*Router, *fakeAuth) {
	t.Helper()
	fa := newFakeAuth()
	r, err := build(Deps{Auth: fa}, files, append(append([]Feature{}, features...), extra...))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return r, fa
}

func do(r http.Handler, method, target string, body url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(body.Encode())
	}
	req := httptest.NewRequest(method, target, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept", "text/html")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

var concretePath = regexp.MustCompile(`\{[^}]*\}`)

// REQ-WEB-001 REQ-WEB-004 REQ-WEB-009
func TestEveryRouteDeclaresAccess(t *testing.T) {
	r, fa := newTestRouter(t)
	routes := r.Routes()
	if len(routes) == 0 {
		t.Fatal("no routes registered")
	}
	viewer := fa.session(t, "victor")
	public := map[string]bool{}
	for _, rt := range routes {
		key := rt.Method + " " + rt.Path
		if err := rt.Access.check(); err != nil {
			t.Errorf("%s: %v", key, err)
			continue
		}
		if rt.Access.IsPublic() {
			public[key] = true
			continue
		}
		target := concretePath.ReplaceAllString(strings.TrimSuffix(rt.Path, "{$}"), "x")
		rec := do(r, rt.Method, target, nil)
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
			t.Errorf("%s without a session = %d Location %q, want 303 to /login", key, rec.Code, rec.Header().Get("Location"))
		}
		if perm, ok := rt.Access.Permission(); ok && perm != auth.PermInventoryRead {
			if rec := do(r, rt.Method, target, nil, viewer); rec.Code != http.StatusForbidden {
				t.Errorf("%s as viewer = %d, want 403", key, rec.Code)
			}
		}
	}
	for _, want := range []string{"GET /login", "POST /login", "GET /healthz", "GET /static/{name}"} {
		if !public[want] {
			t.Errorf("%s is not registered as public", want)
		}
	}
	if len(public) != 4 {
		t.Errorf("public routes = %v, want only login, healthz and static", public)
	}
}

// REQ-WEB-001
func TestUndeclaredRouteFailsStartup(t *testing.T) {
	ok := func(http.ResponseWriter, *http.Request) {}
	cases := map[string]Feature{
		"zero access":        func(r *Router, _ Deps) { r.Handle(http.MethodGet, "/x", Access{}, ok) },
		"unknown permission": func(r *Router, _ Deps) { r.Handle(http.MethodGet, "/x", Require("nope"), ok) },
		"duplicate":          func(r *Router, _ Deps) { r.Handle(http.MethodGet, "/login", Public(), ok) },
		"bad method":         func(r *Router, _ Deps) { r.Handle("", "/x", Public(), ok) },
		"nil handler":        func(r *Router, _ Deps) { r.Handle(http.MethodGet, "/x", Public(), nil) },
		"nav zero access":    func(r *Router, _ Deps) { r.Nav("X", "/x", Access{}) },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := build(Deps{Auth: newFakeAuth()}, files, append(append([]Feature{}, features...), f)); err == nil {
				t.Fatal("build succeeded, want a startup error")
			}
		})
	}
}

// REQ-WEB-002 REQ-WEB-007
func TestEmbeddedTemplatesParse(t *testing.T) {
	if _, err := New(Deps{Auth: newFakeAuth()}); err != nil {
		t.Fatalf("New: %v", err)
	}
}

// REQ-WEB-007
func TestBrokenTemplateFailsStartup(t *testing.T) {
	layout, err := fs.ReadFile(files, "layout.html")
	if err != nil {
		t.Fatal(err)
	}
	errPage, err := fs.ReadFile(files, "error.html")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]fstest.MapFS{
		"syntax error":    {"broken.html": {Data: []byte(`{{define "content"}}{{if}}{{end}}`)}},
		"no content":      {"broken.html": {Data: []byte(`<p>hello</p>`)}},
		"unknown func":    {"broken.html": {Data: []byte(`{{define "content"}}{{nosuch .}}{{end}}`)}},
		"broken layout":   {"layout.html": {Data: []byte(`{{define "layout"}}{{range}}{{end}}`)}},
		"no error page":   {"error.html": nil},
		"no layout block": {"layout.html": {Data: []byte(`<html></html>`)}},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			fsys := fstest.MapFS{"layout.html": {Data: layout}, "error.html": {Data: errPage}}
			for k, v := range extra {
				if v == nil {
					delete(fsys, k)
					continue
				}
				fsys[k] = v
			}
			if _, err := build(Deps{Auth: newFakeAuth()}, fsys, features); err == nil {
				t.Fatal("build succeeded, want a template error")
			}
		})
	}
}

func checkSecurityHeaders(t *testing.T, what string, h http.Header) {
	t.Helper()
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("%s: CSP %q lacks %q", what, csp, want)
		}
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "http:", "https:", "*"} {
		if strings.Contains(csp, bad) {
			t.Errorf("%s: CSP %q allows %q", what, csp, bad)
		}
	}
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "same-origin",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s: %s = %q, want %q", what, k, got, want)
		}
	}
}

// REQ-WEB-008
func TestSecurityHeaders(t *testing.T) {
	r, fa := newTestRouter(t)
	admin := fa.session(t, "alice")
	viewer := fa.session(t, "victor")
	cases := []struct {
		name   string
		method string
		target string
		cookie *http.Cookie
		status int
	}{
		{"login page", http.MethodGet, "/login", nil, http.StatusOK},
		{"dashboard", http.MethodGet, "/", admin, http.StatusOK},
		{"static file", http.MethodGet, "/static/app.css", nil, http.StatusOK},
		{"redirect to login", http.MethodGet, "/", nil, http.StatusSeeOther},
		{"404 page", http.MethodGet, "/no/such/page", admin, http.StatusNotFound},
		{"403 csrf page", http.MethodPost, "/logout", viewer, http.StatusForbidden},
	}
	for _, c := range cases {
		var cookies []*http.Cookie
		if c.cookie != nil {
			cookies = append(cookies, c.cookie)
		}
		rec := do(r, c.method, c.target, nil, cookies...)
		if rec.Code != c.status {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.status)
		}
		checkSecurityHeaders(t, c.name, rec.Header())
	}
}

// REQ-WEB-004 REQ-WEB-008
func TestForbiddenRendersErrorPage(t *testing.T) {
	r, fa := newTestRouter(t, func(r *Router, _ Deps) {
		r.Handle(http.MethodGet, "/admin-only", Require(auth.PermUserManage), func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "secret")
		})
	})
	rec := do(r, http.MethodGet, "/admin-only", nil, fa.session(t, "victor"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "403 Forbidden") || !strings.Contains(body, "<html") || strings.Contains(body, "secret") {
		t.Errorf("403 body is not the error page: %s", body)
	}
	checkSecurityHeaders(t, "403 page", rec.Header())
	if rec := do(r, http.MethodGet, "/admin-only", nil, fa.session(t, "alice")); rec.Code != http.StatusOK || rec.Body.String() != "secret" {
		t.Errorf("admin: %d %q, want 200 secret", rec.Code, rec.Body.String())
	}
}

// REQ-WEB-004
func TestUnauthorizedRedirectsToLogin(t *testing.T) {
	r, _ := newTestRouter(t)
	rec := do(r, http.MethodGet, "/", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("GET / = %d %q, want 303 /login", rec.Code, rec.Header().Get("Location"))
	}
	stale := &http.Cookie{Name: auth.SessionCookieName, Value: "expired"}
	rec = do(r, http.MethodGet, "/?tab=1", nil, stale)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?next="+url.QueryEscape("/?tab=1") {
		t.Errorf("GET /?tab=1 = %d %q, want 303 to login with next", rec.Code, rec.Header().Get("Location"))
	}
	if c := cookieNamed(rec, auth.SessionCookieName); c == nil || c.MaxAge >= 0 {
		t.Errorf("stale session cookie not cleared: %v", c)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("HX-Request", "true")
	hx := httptest.NewRecorder()
	r.ServeHTTP(hx, req)
	if hx.Code != http.StatusUnauthorized || hx.Header().Get("HX-Redirect") != "/login" {
		t.Errorf("htmx GET / = %d HX-Redirect %q, want 401 /login", hx.Code, hx.Header().Get("HX-Redirect"))
	}
}

var csrfInput = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// REQ-WEB-003 REQ-WEB-005
func TestLoginLogout(t *testing.T) {
	r, fa := newTestRouter(t)
	page := do(r, http.MethodGet, "/login?next=/hosts%3Fq%3D1", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("GET /login = %d", page.Code)
	}
	m := csrfInput.FindStringSubmatch(page.Body.String())
	loginCookie := cookieNamed(page, loginCSRFCookie)
	if m == nil || loginCookie == nil || loginCookie.Value != m[1] || !loginCookie.HttpOnly {
		t.Fatalf("login form token %v / cookie %v do not match", m, loginCookie)
	}
	if !strings.Contains(page.Body.String(), `name="next" value="/hosts?q=1"`) {
		t.Errorf("login form lacks next: %s", page.Body.String())
	}
	form := func(user, pass, token string) url.Values {
		return url.Values{"username": {user}, "password": {pass}, "csrf_token": {token}, "next": {"/hosts?q=1"}}
	}

	if rec := do(r, http.MethodPost, "/login", form("alice", "alice-password-1", "forged"), loginCookie); rec.Code != http.StatusForbidden {
		t.Errorf("login with forged CSRF = %d, want 403", rec.Code)
	}
	if rec := do(r, http.MethodPost, "/login", form("alice", "alice-password-1", m[1])); rec.Code != http.StatusForbidden {
		t.Errorf("login without CSRF cookie = %d, want 403", rec.Code)
	}
	rec := do(r, http.MethodPost, "/login", form("alice", "wrong-password", m[1]), loginCookie)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Invalid username or password") {
		t.Errorf("bad password = %d, want 401 with a message", rec.Code)
	}
	if cookieNamed(rec, auth.SessionCookieName) != nil {
		t.Error("bad password set a session cookie")
	}
	if rec := do(r, http.MethodPost, "/login", form("limited", "x", m[1]), loginCookie); rec.Code != http.StatusTooManyRequests {
		t.Errorf("rate limited = %d, want 429", rec.Code)
	}

	rec = do(r, http.MethodPost, "/login", form("alice", "alice-password-1", m[1]), loginCookie)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/hosts?q=1" {
		t.Fatalf("login = %d %q, want 303 to next", rec.Code, rec.Header().Get("Location"))
	}
	sess := cookieNamed(rec, auth.SessionCookieName)
	if sess == nil || sess.Value != "tok-alice" || !sess.HttpOnly {
		t.Fatalf("session cookie = %v", sess)
	}

	if rec := do(r, http.MethodPost, "/logout", url.Values{}, sess); rec.Code != http.StatusForbidden {
		t.Errorf("logout without CSRF = %d, want 403", rec.Code)
	}
	if len(fa.loggedOut) != 0 {
		t.Fatalf("logout without CSRF ended the session")
	}
	rec = do(r, http.MethodPost, "/logout", url.Values{"csrf_token": {"csrf-alice"}}, sess)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("logout = %d %q, want 303 /login", rec.Code, rec.Header().Get("Location"))
	}
	if c := cookieNamed(rec, auth.SessionCookieName); c == nil || c.MaxAge >= 0 {
		t.Errorf("logout did not clear the cookie: %v", c)
	}
	if len(fa.loggedOut) != 1 || fa.loggedOut[0] != "tok-alice" {
		t.Errorf("logged out = %v", fa.loggedOut)
	}
	if rec := do(r, http.MethodGet, "/", nil, sess); rec.Code != http.StatusSeeOther {
		t.Errorf("dashboard after logout = %d, want 303", rec.Code)
	}
}

// REQ-WEB-003
func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/hosts":            "/hosts",
		"":                  "",
		"//evil.example/":   "",
		"/\t/evil.example/": "",
		"/\n/evil.example/": "",
		"/\x00/evil":        "",
		"/\x7f/evil":        "",
		"https://evil.ex/":  "",
		"/\\evil.example":   "",
		"hosts":             "",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

// REQ-WEB-009 REQ-WEB-005
func TestDashboardShowsUserAndRole(t *testing.T) {
	r, fa := newTestRouter(t)
	rec := do(r, http.MethodGet, "/", nil, fa.session(t, "victor"))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`<strong class="username">victor</strong>`, `<strong class="role">viewer</strong>`,
		`hx-headers='{"X-CSRF-Token": "csrf-victor"}'`, `<input type="hidden" name="csrf_token" value="csrf-victor">`} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %q:\n%s", want, body)
		}
	}
}

// REQ-WEB-006
func TestNavShowsOnlyAllowedEntries(t *testing.T) {
	ok := func(http.ResponseWriter, *http.Request) {}
	r, fa := newTestRouter(t, func(r *Router, _ Deps) {
		r.Nav("Users", "/users", Require(auth.PermUserManage))
		r.Handle(http.MethodGet, "/users", Require(auth.PermUserManage), ok)
		r.Nav("Hosts", "/hosts", Require(auth.PermInventoryRead))
		r.Handle(http.MethodGet, "/hosts", Require(auth.PermInventoryRead), ok)
	})
	for user, want := range map[string]map[string]bool{
		"alice":  {"/": true, "/hosts": true, "/users": true},
		"victor": {"/": true, "/hosts": true, "/users": false},
	} {
		body := do(r, http.MethodGet, "/", nil, fa.session(t, user)).Body.String()
		for path, shown := range want {
			if got := strings.Contains(body, `<a href="`+path+`"`); got != shown {
				t.Errorf("%s: nav entry %s shown = %v, want %v", user, path, got, shown)
			}
		}
	}
	login := do(r, http.MethodGet, "/login", nil).Body.String()
	if strings.Contains(login, `<nav>`) {
		t.Errorf("anonymous login page shows navigation")
	}
}

func TestNavMarksCurrentSection(t *testing.T) {
	r, fa := newTestRouter(t)
	p, err := fa.LookupSession(context.Background(), fa.session(t, "alice").Value)
	if err != nil {
		t.Fatal(err)
	}
	current := regexp.MustCompile(`<a href="([^"]*)" aria-current="page">`)
	for path, want := range map[string]string{
		"/":                        "/",
		"/hosts/":                  "/hosts/",
		"/hosts/10.0.0.1":          "/hosts/",
		"/hosts/10.0.0.1/timeline": "/hosts/",
		"/hosts/entry":             "/hosts/",
		"/changes":                 "/changes",
		"/scans":                   "/scans",
		"/scans/42":                "/scans",
		"/runs/42":                 "/scans",
		"/runs":                    "/scans",
		"/groups":                  "/groups",
		"/signatures/7":            "/signatures",
		"/import":                  "/import",
		"/export":                  "/export",
		"/hostsx":                  "",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		rec := httptest.NewRecorder()
		r.Error(rec, req, http.StatusNotFound, "x")
		got := current.FindAllStringSubmatch(rec.Body.String(), -1)
		if want == "" {
			if len(got) != 0 {
				t.Errorf("%s: marked %v, want none", path, got)
			}
			continue
		}
		if len(got) != 1 || got[0][1] != want {
			t.Errorf("%s: marked %v, want exactly %s", path, got, want)
		}
	}
}

var externalRef = regexp.MustCompile(`(?i)(src|href|action)\s*=\s*["']?\s*(https?:)?//`)

// REQ-WEB-007
func TestNoExternalResources(t *testing.T) {
	r, fa := newTestRouter(t)
	admin := fa.session(t, "alice")
	pages := map[string]string{
		"login":     do(r, http.MethodGet, "/login", nil).Body.String(),
		"dashboard": do(r, http.MethodGet, "/", nil, admin).Body.String(),
		"error":     do(r, http.MethodGet, "/nope", nil, admin).Body.String(),
	}
	for name, body := range pages {
		if externalRef.MatchString(body) {
			t.Errorf("%s references an external resource: %s", name, externalRef.FindString(body))
		}
		for _, want := range []string{`<script src="/static/htmx.min.js" defer></script>`, `<link rel="stylesheet" href="/static/app.css">`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %s", name, want)
			}
		}
		if regexp.MustCompile(`<script>|<script [^>]*>[^<]`).MatchString(body) || strings.Contains(body, "style=") {
			t.Errorf("%s has inline script or style", name)
		}
	}
	css := do(r, http.MethodGet, "/static/app.css", nil).Body.String()
	if strings.Contains(css, "url(") || strings.Contains(css, "@import") {
		t.Error("app.css loads external resources")
	}
	js := do(r, http.MethodGet, "/static/htmx.min.js", nil)
	if js.Code != http.StatusOK || !strings.Contains(js.Body.String(), "htmx") ||
		!strings.Contains(js.Header().Get("Content-Type"), "javascript") {
		t.Errorf("htmx.min.js = %d %q", js.Code, js.Header().Get("Content-Type"))
	}
	if rec := do(r, http.MethodGet, "/static/", nil); rec.Code != http.StatusNotFound {
		t.Errorf("GET /static/ = %d, want 404 (no listing)", rec.Code)
	}
	if rec := do(r, http.MethodGet, "/static/nope.js", nil); rec.Code != http.StatusNotFound {
		t.Errorf("GET /static/nope.js = %d, want 404", rec.Code)
	}
}

// REQ-WEB-003
func TestLoginIgnoresUnsafeNext(t *testing.T) {
	r, _ := newTestRouter(t)
	page := do(r, http.MethodGet, "/login?next=%2F%09%2Fevil.example%2F", nil)
	m := csrfInput.FindStringSubmatch(page.Body.String())
	loginCookie := cookieNamed(page, loginCSRFCookie)
	if m == nil || loginCookie == nil {
		t.Fatal("login form has no CSRF token")
	}
	if strings.Contains(page.Body.String(), "evil.example") {
		t.Errorf("login form keeps the unsafe next")
	}
	form := url.Values{"username": {"alice"}, "password": {"alice-password-1"}, "csrf_token": {m[1]}, "next": {"/\t/evil.example/"}}
	rec := do(r, http.MethodPost, "/login", form, loginCookie)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Errorf("login with next=/\\t/evil.example/ = %d %q, want 303 to /", rec.Code, rec.Header().Get("Location"))
	}
}

var chartRunRE = regexp.MustCompile(`<g data-run="([^"]+)" data-new="(\d+)" data-missing="(\d+)" data-changed="(\d+)"><title>([^<]+)</title>`)

// REQ-WEB-015
func TestDashboardChangeChart(t *testing.T) {
	inv := &fakeInventory{exports: map[string]inventory.Export{}}
	for i := 0; i < 22; i++ {
		name := fmt.Sprintf("c%02d", i)
		var hosts []inventory.ExportHost
		for j := 0; j <= i%4; j++ {
			hosts = append(hosts, inventory.ExportHost{Address: fmt.Sprintf("10.0.0.%d", j+1), Status: inventory.StatusActive})
		}
		inv.runs = append([]inventory.Run{{ID: int64(i + 1), Name: name, Status: inventory.RunCompleted}}, inv.runs...)
		inv.exports[name] = inventory.Export{Run: name, Hosts: hosts}
	}
	inv.runs = append([]inventory.Run{{ID: 99, Name: "running", Status: inventory.RunRunning}}, inv.runs...)
	r, viewer := newChangesRouter(t, inv)
	rec := do(r, http.MethodGet, "/", nil, viewer)
	body := rec.Body.String()
	m := chartRunRE.FindAllStringSubmatch(body, -1)
	if rec.Code != http.StatusOK || len(m) != 20 || m[0][1] != "c02" || m[19][1] != "c21" {
		t.Fatalf("chart has %d runs (status %d):\n%s", len(m), rec.Code, body)
	}
	if m[1][2] != "1" || m[0][5] != "c02: 1 new, 0 missing, 0 changed (against c01)" {
		t.Errorf("chart values = %v", m[:2])
	}
	if !strings.Contains(body, `<svg class="chart" role="img"`) || strings.Contains(body, "style=") || externalRef.MatchString(body) {
		t.Errorf("chart markup:\n%s", body)
	}

	few := &fakeInventory{runs: inv.runs[len(inv.runs)-3:], exports: inv.exports}
	r, viewer = newChangesRouter(t, few)
	if m := chartRunRE.FindAllStringSubmatch(do(r, http.MethodGet, "/", nil, viewer).Body.String(), -1); len(m) != 2 {
		t.Errorf("3 runs: chart has %d entries, want 2", len(m))
	}
	r, viewer = newChangesRouter(t, &fakeInventory{})
	if body := do(r, http.MethodGet, "/", nil, viewer).Body.String(); !strings.Contains(body, "A chart of changes per run appears here once two scan runs have completed.") || strings.Contains(body, "<svg") {
		t.Errorf("no empty state:\n%s", body)
	}
}

// REQ-WEB-015
func TestChangeChartGeometry(t *testing.T) {
	c := newChangeChart([]diff.RunCounts{{From: "a", To: "b", New: 4, Missing: 1, Changed: 0}, {From: "b", To: "c", New: 0, Missing: 0, Changed: 2}})
	if c.Max != 4 || len(c.Runs) != 2 {
		t.Fatalf("chart = %+v", c)
	}
	bars := c.Runs[0].Bars
	if bars[0].Height != chartPlot || bars[0].Y != c.AxisY-chartPlot || bars[1].Height != chartPlot/4 || bars[2].Height != 0 {
		t.Errorf("bars = %+v", bars)
	}
	if c.Runs[1].Bars[0].X <= bars[2].X {
		t.Errorf("runs overlap: %+v", c.Runs)
	}
}

// REQ-SIGNATURES-005
func TestSignaturePagesForbiddenToViewerAndOperator(t *testing.T) {
	r, fa := newTestRouter(t)
	fa.passwords["olga"] = "olga-password-1"
	fa.roles["olga"] = auth.Principal{Username: "olga", Role: auth.RoleOperator,
		Permissions: []auth.Permission{auth.PermInventoryEdit, auth.PermInventoryRead, auth.PermExport}}
	n := 0
	for _, rt := range r.Routes() {
		if !strings.HasPrefix(rt.Path, "/signatures") {
			continue
		}
		n++
		if perm, _ := rt.Access.Permission(); perm != auth.PermSignatureManage {
			t.Errorf("%s %s access = %s, want signature.manage", rt.Method, rt.Path, rt.Access)
		}
		target := concretePath.ReplaceAllString(rt.Path, "x")
		for _, user := range []string{"victor", "olga"} {
			cookie := fa.session(t, user)
			body := url.Values{auth.CSRFFormField: {"csrf-" + user}, "source": {"id: x"}}
			if rt.Method == http.MethodGet {
				body = nil
			}
			if rec := do(r, rt.Method, target, body, cookie); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s as %s = %d, want 403", rt.Method, target, user, rec.Code)
			}
		}
	}
	if n < 10 {
		t.Fatalf("%d signature routes, want list, new, create, edit, update, enable, disable, delete, test, import, export", n)
	}
	rec := do(r, http.MethodGet, "/", nil, fa.session(t, "olga"))
	if strings.Contains(rec.Body.String(), `href="/signatures"`) {
		t.Error("operator sees the Signatures nav entry")
	}
	rec = do(r, http.MethodGet, "/", nil, fa.session(t, "alice"))
	if !strings.Contains(rec.Body.String(), `href="/signatures"`) {
		t.Error("admin does not see the Signatures nav entry")
	}
}

// REQ-WEB-001 REQ-SIGNATURES-026
func TestRoutesDeclareEveryRequiredPermission(t *testing.T) {
	r, _ := newTestRouter(t)
	sig, read, exp, del := auth.PermSignatureManage, auth.PermInventoryRead, auth.PermExport, auth.PermInventoryDelete
	want := map[string][]auth.Permission{
		"POST /signatures/test":                                   {sig, read},
		"POST /signatures/hunt":                                   {sig, read},
		"GET /signatures/hunts/{id}":                              {sig, read},
		"POST /signatures/hunts/{id}/save":                        {sig, read},
		"GET /signatures/hunts/{id}/csv":                          {sig, read, exp},
		"GET /hosts/{address}/delete":                             {del, read},
		"GET /hosts/{address}/services/{port}/{protocol}/delete":  {del, read},
		"POST /hosts/{address}/delete":                            {del},
		"POST /hosts/{address}/services/{port}/{protocol}/delete": {del},
		"GET /signatures":                                         {sig},
		"GET /signatures/new":                                     {sig},
		"GET /signatures/export":                                  {sig},
		"POST /defectdojo/settings":                               {auth.PermScanConfigure},
		"GET /defectdojo":                                         {exp},
	}
	seen := 0
	for _, rt := range r.Routes() {
		key := rt.Method + " " + rt.Path
		perms, ok := want[key]
		if !ok {
			continue
		}
		seen++
		got := rt.Access.Permissions()
		if fmt.Sprint(got) != fmt.Sprint(perms) {
			t.Errorf("%s requires %v, want %v", key, got, perms)
		}
		if first, gated := rt.Access.Permission(); !gated || first != perms[0] {
			t.Errorf("%s Permission() = %q %v, want %q true", key, first, gated, perms[0])
		}
		for _, p := range perms {
			if !strings.Contains(rt.Access.String(), string(p)) {
				t.Errorf("%s access %q does not name %s", key, rt.Access, p)
			}
		}
	}
	if seen != len(want) {
		t.Errorf("found %d of %d declared routes", seen, len(want))
	}
	if p, gated := SignedIn().Permission(); gated || p != "" {
		t.Errorf("SignedIn().Permission() = %q %v, want none", p, gated)
	}
	if got := Require(sig, read).String(); got != "permissions signature.manage + inventory.read" {
		t.Errorf("String() = %q", got)
	}
	if got := Require(read).String(); got != "permission inventory.read" {
		t.Errorf("String() = %q", got)
	}
}

// REQ-WEB-001
func TestMultiPermissionAccessNeedsAll(t *testing.T) {
	ok := func(http.ResponseWriter, *http.Request) {}
	if _, err := build(Deps{Auth: newFakeAuth()}, files, append(append([]Feature{}, features...), func(r *Router, _ Deps) {
		r.Handle(http.MethodGet, "/x", Require(auth.PermInventoryRead, "nope"), ok)
	})); err == nil {
		t.Fatal("build accepted an unknown permission in the second position")
	}
	r, fa := newTestRouter(t, func(r *Router, _ Deps) {
		r.Handle(http.MethodGet, "/both", Require(auth.PermInventoryRead, auth.PermExport), ok)
	})
	fa.passwords["erin"] = "erin-password-1"
	fa.roles["erin"] = auth.Principal{Username: "erin", Role: "custom", Permissions: []auth.Permission{auth.PermExport}}
	for user, want := range map[string]int{"victor": http.StatusForbidden, "erin": http.StatusForbidden, "alice": http.StatusOK} {
		if rec := do(r, http.MethodGet, "/both", nil, fa.session(t, user)); rec.Code != want {
			t.Errorf("GET /both as %s = %d, want %d", user, rec.Code, want)
		}
	}
}

var navGroupRE = regexp.MustCompile(`<div class="nav-group">(?:<h2 class="nav-heading">([^<]*)</h2>)?(.*?)</div>`)
var navEntryRE = regexp.MustCompile(`<a href="([^"]*)"[^>]*>([^<]*)</a>`)

func navLayout(t *testing.T, page string) []string {
	t.Helper()
	nav := regexp.MustCompile(`(?s)<nav aria-label="Main">(.*?)</nav>`).FindStringSubmatch(page)
	if nav == nil {
		t.Fatalf("page has no main navigation:\n%s", page)
	}
	var got []string
	for _, g := range navGroupRE.FindAllStringSubmatch(nav[1], -1) {
		entries := []string{}
		for _, e := range navEntryRE.FindAllStringSubmatch(g[2], -1) {
			entries = append(entries, e[2]+" "+e[1])
		}
		got = append(got, g[1]+": "+strings.Join(entries, ", "))
	}
	if rest := navGroupRE.ReplaceAllString(nav[1], ""); strings.TrimSpace(rest) != "" {
		t.Errorf("navigation has markup outside its groups: %q", rest)
	}
	return got
}

var adminNavLayout = []string{
	"Overview: Dashboard /, Changes /changes",
	"Inventory: Hosts /hosts/, Groups /groups",
	"Scanning: Scans /scans, Signatures /signatures",
	"Data: Import /import, Export /export, DefectDojo /defectdojo",
	"Administration: Users /users/, Roles /roles, Audit log /audit",
}

// REQ-WEB-006
func TestNavGroupsInFixedOrder(t *testing.T) {
	r, fa := newTestRouter(t)
	page := do(r, http.MethodGet, "/", nil, fa.session(t, "alice")).Body.String()
	if got := navLayout(t, page); !slices.Equal(got, adminNavLayout) {
		t.Errorf("admin navigation =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(adminNavLayout, "\n"))
	}
	if strings.Contains(page, "Add host") {
		t.Error("navigation still has an Add host entry")
	}
	if regexp.MustCompile(`style\s*=`).MatchString(page) {
		t.Error("layout has inline styles")
	}

	reversed := slices.Clone(features)
	slices.Reverse(reversed[1:])
	rr, err := build(Deps{Auth: fa}, files, reversed)
	if err != nil {
		t.Fatal(err)
	}
	var headings []string
	for _, g := range navLayout(t, do(rr, http.MethodGet, "/", nil, fa.session(t, "alice")).Body.String()) {
		headings = append(headings, g[:strings.Index(g, ":")])
	}
	if want := []string{"Overview", "Inventory", "Scanning", "Data", "Administration"}; !slices.Equal(headings, want) {
		t.Errorf("headings with features registered in reverse = %v, want %v", headings, want)
	}

	viewer := navLayout(t, do(r, http.MethodGet, "/", nil, fa.session(t, "victor")).Body.String())
	if want := adminNavLayout[:2]; !slices.Equal(viewer, want) {
		t.Errorf("viewer navigation = %v, want %v", viewer, want)
	}
}

func TestNavRejectsUnknownGroup(t *testing.T) {
	fa := newFakeAuth()
	_, err := build(Deps{Auth: fa}, files, []Feature{RegisterShell, func(r *Router, _ Deps) {
		r.NavIn(NavGroup(99), "X", "/x", SignedIn())
	}})
	if err == nil || !strings.Contains(err.Error(), "unknown group") {
		t.Fatalf("build = %v, want an unknown group error", err)
	}
}
