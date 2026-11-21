# UI conventions

The web UI lives in `internal/web`: server-rendered `html/template`, htmx and one CSS file, all embedded. No CDN,
no inline script, no Node toolchain.

## Add a page

1. Create `internal/web/<feature>.go` with one exported function and register it in the `features` slice in
   `internal/web/web.go` (one line per feature, nothing else changes there):

   ```go
   func RegisterInventory(r *Router, d Deps) {
       r.Nav("Hosts", "/hosts", Require(auth.PermInventoryRead))
       r.Handle(http.MethodGet, "/hosts", Require(auth.PermInventoryRead), func(w http.ResponseWriter, req *http.Request) {
           r.Render(w, req, http.StatusOK, "inventory.html", View{Title: "Hosts", Data: hosts})
       })
   }
   ```

2. Every route declares its access as the third argument: `Public()`, `SignedIn()` (any signed-in user) or
   `Require(permission)` with a permission from `internal/auth`. A missing or unknown access, a duplicate route or a
   nil handler makes `web.New` (and so `asi serve`) fail at startup, and `TestEveryRouteDeclaresAccess` walks all
   routes.
3. The router does the rest: no session → redirect to `/login` (htmx: 401 + `HX-Redirect`); missing permission →
   403 error page; non-GET requests need the CSRF token. Handlers read the user with `auth.PrincipalFrom(req.Context())`
   and report failures with `r.Error(w, req, status, message)` or `r.ServerError(w, req, err)`.
4. `Deps` carries the store, the keyring and the auth service. Add a field only if a feature needs something new.

## Add a nav entry

Call `r.Nav(label, path, access)` from the feature's register function. Entries appear in registration order and
only for users whose role satisfies `access`; use the same access as the page.

## Add a template

- Put `<feature>.html` next to `<feature>.go` in `internal/web`. Every `*.html` file there except `layout.html` is a
  page: it must `{{define "content"}}…{{end}}`, which `layout.html` renders inside the shell. Files are embedded and
  parsed at startup; a broken template fails startup and `TestEmbeddedTemplatesParse`.
- Template data is a `View`: `.Title`, `.User` (the signed-in `auth.Principal`), `.Nav`, `.CSRFToken`, `.Data`
  (your page data).
- Forms that POST include `{{.CSRFField}}`. htmx requests get the token automatically from `hx-headers` on `<body>`.
- No `<script>` blocks, `style=` attributes, `hx-on` handlers or external URLs: the Content-Security-Policy blocks them.
  Styles go in `internal/web/static/app.css`; files in `internal/web/static/` are served under `/static/`.
