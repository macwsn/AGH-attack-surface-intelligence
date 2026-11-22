package web

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"asi/internal/auth"
)

type accessKind int

const (
	accessUndeclared accessKind = iota
	accessPublic
	accessSignedIn
	accessPermission
)

type Access struct {
	kind  accessKind
	perms []auth.Permission
}

func Public() Access { return Access{kind: accessPublic} }

func SignedIn() Access { return Access{kind: accessSignedIn} }

func Require(p auth.Permission, more ...auth.Permission) Access {
	return Access{kind: accessPermission, perms: append([]auth.Permission{p}, more...)}
}

func (a Access) IsPublic() bool { return a.kind == accessPublic }

func (a Access) Permission() (auth.Permission, bool) {
	if a.kind != accessPermission || len(a.perms) == 0 {
		return "", false
	}
	return a.perms[0], true
}

func (a Access) Permissions() []auth.Permission { return slices.Clone(a.perms) }

func (a Access) String() string {
	switch a.kind {
	case accessPublic:
		return "public"
	case accessSignedIn:
		return "signed-in"
	case accessPermission:
		names := make([]string, len(a.perms))
		for i, p := range a.perms {
			names[i] = string(p)
		}
		if len(names) > 1 {
			return "permissions " + strings.Join(names, " + ")
		}
		return "permission " + strings.Join(names, "")
	}
	return "undeclared"
}

func (a Access) check() error {
	switch a.kind {
	case accessPublic, accessSignedIn:
		return nil
	case accessPermission:
		if len(a.perms) == 0 {
			return errors.New("no permission declared")
		}
		for _, p := range a.perms {
			if !slices.Contains(auth.AllPermissions, p) {
				return fmt.Errorf("%w: %q", auth.ErrUnknownPermission, p)
			}
		}
		return nil
	}
	return errors.New("no access declared: use web.Public(), web.SignedIn() or web.Require(permission)")
}

func (a Access) allows(p *auth.Principal) bool {
	switch a.kind {
	case accessPublic:
		return true
	case accessSignedIn:
		return p != nil
	case accessPermission:
		if p == nil || len(a.perms) == 0 {
			return false
		}
		for _, perm := range a.perms {
			if !slices.Contains(p.Permissions, perm) {
				return false
			}
		}
		return true
	}
	return false
}

type Route struct {
	Method  string
	Path    string
	Access  Access
	handler http.Handler
}

type NavGroup int

const (
	NavNone NavGroup = iota
	NavOverview
	NavInventory
	NavScanning
	NavData
	NavAdministration
)

var navHeadings = []string{NavOverview: "Overview", NavInventory: "Inventory", NavScanning: "Scanning",
	NavData: "Data", NavAdministration: "Administration"}

type NavSection struct {
	Heading string
	Entries []NavEntry
}

type NavEntry struct {
	Group   NavGroup
	Label   string
	Path    string
	Access  Access
	Current bool
	Also    []string
}

type Router struct {
	auth   Auth
	pages  map[string]*template.Template
	static fs.FS
	routes []Route
	nav    []NavEntry
	errs   []error
	mux    *http.ServeMux
}

var routeMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

func (r *Router) Handle(method, path string, access Access, h http.HandlerFunc) {
	if err := r.checkRoute(method, path, access, h); err != nil {
		r.errs = append(r.errs, fmt.Errorf("route %s %s: %w", method, path, err))
		return
	}
	r.routes = append(r.routes, Route{Method: method, Path: path, Access: access, handler: h})
}

func (r *Router) checkRoute(method, path string, access Access, h http.HandlerFunc) error {
	if !slices.Contains(routeMethods, method) {
		return fmt.Errorf("method must be one of %s", strings.Join(routeMethods, ", "))
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t") {
		return errors.New("path must start with / and contain no spaces")
	}
	if h == nil {
		return errors.New("nil handler")
	}
	for _, rt := range r.routes {
		if rt.Method == method && rt.Path == path {
			return errors.New("registered twice")
		}
	}
	return access.check()
}

func (r *Router) Nav(label, path string, access Access, also ...string) {
	r.NavIn(NavNone, label, path, access, also...)
}

func (r *Router) NavIn(g NavGroup, label, path string, access Access, also ...string) {
	if g < NavNone || int(g) >= len(navHeadings) {
		r.errs = append(r.errs, fmt.Errorf("nav entry %q: unknown group %d", label, g))
		return
	}
	if err := access.check(); err != nil {
		r.errs = append(r.errs, fmt.Errorf("nav entry %q: %w", label, err))
		return
	}
	r.nav = append(r.nav, NavEntry{Group: g, Label: label, Path: path, Access: access, Also: also})
}

func (r *Router) Routes() []Route { return slices.Clone(r.routes) }

func (r *Router) finish() error {
	if err := errors.Join(r.errs...); err != nil {
		return fmt.Errorf("web routes: %w", err)
	}
	r.mux = http.NewServeMux()
	for _, rt := range r.routes {
		r.mux.Handle(rt.Method+" "+rt.Path, r.guard(rt))
	}
	r.mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		r.Error(w, req, http.StatusNotFound, "This page does not exist.")
	})
	return nil
}

const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	r.mux.ServeHTTP(w, req)
}

func (r *Router) guard(rt Route) http.Handler {
	if rt.Access.IsPublic() {
		return rt.handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p, err := r.principal(req)
		if errors.Is(err, auth.ErrNoSession) {
			r.unauthorized(w, req)
			return
		}
		if err != nil {
			r.ServerError(w, req, fmt.Errorf("look up session: %w", err))
			return
		}
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		if !rt.Access.allows(&p) {
			r.Error(w, req, http.StatusForbidden, "Your role does not allow this page.")
			return
		}
		if req.Method != http.MethodGet && req.Method != http.MethodHead && !validCSRF(req, p.CSRFToken) {
			r.Error(w, req, http.StatusForbidden, "Invalid or missing CSRF token. Reload the page and try again.")
			return
		}
		rt.handler.ServeHTTP(w, req)
	})
}

const csrfPeekBytes = 64 << 10

func validCSRF(req *http.Request, want string) bool {
	mt, params, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if mt != "multipart/form-data" || req.Header.Get(auth.CSRFHeader) != "" {
		return auth.ValidCSRF(req, want)
	}
	if params["boundary"] == "" || want == "" {
		return false
	}
	body := req.Body
	var seen bytes.Buffer
	mr := multipart.NewReader(io.TeeReader(io.LimitReader(body, csrfPeekBytes), &seen), params["boundary"])
	ok := false
	for {
		part, err := mr.NextPart()
		if err != nil || part.FileName() != "" {
			break
		}
		if part.FormName() == auth.CSRFFormField {
			got, err := io.ReadAll(io.LimitReader(part, 256))
			ok = err == nil && subtle.ConstantTimeCompare(got, []byte(want)) == 1
			break
		}
	}
	req.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(&seen, body), body}
	return ok
}

func (r *Router) principal(req *http.Request) (auth.Principal, error) {
	c, err := req.Cookie(auth.SessionCookieName)
	if err != nil {
		return auth.Principal{}, auth.ErrNoSession
	}
	return r.auth.LookupSession(req.Context(), c.Value)
}

func (r *Router) unauthorized(w http.ResponseWriter, req *http.Request) {
	if _, err := req.Cookie(auth.SessionCookieName); err == nil {
		r.auth.ClearSessionCookie(w, req)
	}
	target := "/login"
	if req.Method == http.MethodGet && req.URL.RequestURI() != "/" {
		target += "?next=" + url.QueryEscape(req.URL.RequestURI())
	}
	if req.Header.Get("HX-Request") != "" {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	http.Redirect(w, req, target, http.StatusSeeOther)
}

type View struct {
	Title     string
	User      *auth.Principal
	Nav       []NavSection
	CSRFToken string
	Data      any
}

func (v View) CSRFField() template.HTML {
	return template.HTML(`<input type="hidden" name="` + auth.CSRFFormField + `" value="` +
		template.HTMLEscapeString(v.CSRFToken) + `">`)
}

func (r *Router) Render(w http.ResponseWriter, req *http.Request, status int, page string, v View) {
	t, ok := r.pages[page]
	if !ok {
		r.ServerError(w, req, fmt.Errorf("render: unknown template %q", page))
		return
	}
	r.withUser(req, &v)
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", v); err != nil {
		r.ServerError(w, req, fmt.Errorf("render %s: %w", page, err))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (r *Router) withUser(req *http.Request, v *View) {
	p, ok := auth.PrincipalFrom(req.Context())
	if !ok {
		return
	}
	v.User = &p
	if v.CSRFToken == "" {
		v.CSRFToken = p.CSRFToken
	}
	var shown []NavEntry
	cur, best := -1, 0
	for _, n := range r.nav {
		if n.Access.allows(&p) {
			for _, prefix := range append([]string{n.Path}, n.Also...) {
				if navMatches(prefix, req.URL.Path) && len(prefix) > best {
					cur, best = len(shown), len(prefix)
				}
			}
			shown = append(shown, n)
		}
	}
	if cur >= 0 {
		shown[cur].Current = true
	}
	for g := range navHeadings {
		var sec NavSection
		for _, n := range shown {
			if int(n.Group) == g {
				sec.Entries = append(sec.Entries, n)
			}
		}
		if len(sec.Entries) > 0 {
			sec.Heading = navHeadings[g]
			v.Nav = append(v.Nav, sec)
		}
	}
}

func navMatches(navPath, path string) bool {
	if navPath == "/" {
		return path == "/"
	}
	base := strings.TrimSuffix(navPath, "/")
	return path == base || strings.HasPrefix(path, base+"/")
}

type errorData struct {
	Status  int
	Text    string
	Message string
}

func (r *Router) Error(w http.ResponseWriter, req *http.Request, status int, message string) {
	t, ok := r.pages["error.html"]
	var buf bytes.Buffer
	if ok {
		v := View{Title: http.StatusText(status), Data: errorData{Status: status, Text: http.StatusText(status), Message: message}}
		r.withUser(req, &v)
		ok = t.ExecuteTemplate(&buf, "layout", v) == nil
	}
	if !ok {
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (r *Router) ServerError(w http.ResponseWriter, req *http.Request, err error) {
	log.Printf("web: %s %s: %v", req.Method, req.URL.Path, err)
	r.Error(w, req, http.StatusInternalServerError, "Something went wrong.")
}

const layoutFile = "layout.html"

func parsePages(fsys fs.FS) (map[string]*template.Template, error) {
	base, err := template.New(layoutFile).Funcs(template.FuncMap{"zoned": isoTime}).ParseFS(fsys, layoutFile)
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	if base.Lookup("layout") == nil {
		return nil, fmt.Errorf("parse templates: %s does not define \"layout\"", layoutFile)
	}
	for _, p := range partials {
		if _, err := fs.Stat(fsys, p); err != nil {
			continue
		}
		if base, err = base.ParseFS(fsys, p); err != nil {
			return nil, fmt.Errorf("parse template %s: %w", p, err)
		}
	}
	names, err := fs.Glob(fsys, "*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	pages := make(map[string]*template.Template, len(names))
	for _, name := range names {
		if name == layoutFile || slices.Contains(partials, name) {
			continue
		}
		t, err := base.Clone()
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		if t, err = t.ParseFS(fsys, name); err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		if t.Lookup("content") == nil {
			return nil, fmt.Errorf("parse template %s: it does not define \"content\"", name)
		}
		pages[name] = t
	}
	if _, ok := pages["error.html"]; !ok {
		return nil, errors.New("parse templates: error.html is missing")
	}
	return pages, nil
}
