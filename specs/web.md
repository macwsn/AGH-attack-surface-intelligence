---
capability: web
title: Web UI shell
code: []
tests: []
---
# Web UI shell

## Requirements

### REQ-WEB-001: Every route declares its access
The system SHALL register every UI route through `Router.Handle(method, path, access, handler)` where access is `web.Public()`, `web.SignedIn()` or `web.Require(permission)`, and `web.New` SHALL fail at startup when a route or nav entry has no declared access, an unknown permission, an unsupported method, a nil handler or a duplicate method and path.

#### Scenario: undeclared access
- WHEN a feature registers a route with the zero `web.Access{}`
- THEN `web.New` returns an error and `asi serve` does not start

### REQ-WEB-002: Feature registry
The system SHALL build the UI from the `features` slice in `internal/web/web.go`, one `Register<Feature>(r *Router, d Deps)` function per line, each defined in the feature's own file; `docs/ui-conventions.md` SHALL describe how to add a page, a nav entry and a template.

### REQ-WEB-003: Login and logout
The system SHALL serve `GET /login` and `POST /login` publicly, sign users in through `internal/auth`, set the session cookie and redirect with 303 to a local `next` path or `/`; a failed login SHALL re-render the form with 401 (wrong credentials) or 429 (rate limited). `POST /login` SHALL require a CSRF token matching the `asi_login_csrf` cookie set by the form. `POST /logout` SHALL require a session and its CSRF token, end the session and redirect to `/login`.

#### Scenario: open redirect
- WHEN `next` is not a local path (for example `//evil.example/`) or contains a backslash or an ASCII control character (for example `/\t/evil.example/`)
- THEN login redirects to `/`

### REQ-WEB-004: Sessions, 401 and 403
The system SHALL require a valid session for every non-public route; without one a browser request SHALL be redirected with 303 to `/login` (with `next` for GET requests other than `/`), an htmx request SHALL get 401 with `HX-Redirect: /login`, and a stale session cookie SHALL be cleared. A signed-in user lacking the route's permission SHALL get a 403 HTML error page.

### REQ-WEB-005: CSRF
The system SHALL reject non-GET/HEAD requests on non-public routes with 403 unless they carry the session's CSRF token in the `X-CSRF-Token` header or the `csrf_token` form field; templates SHALL get the token as `.CSRFToken` and a hidden form field as `.CSRFField`, and the layout SHALL send the token on htmx requests through `hx-headers`.

### REQ-WEB-006: Navigation by permission
The system SHALL show in the layout navigation only the nav entries whose access the signed-in user's role satisfies, and no navigation to anonymous users.

### REQ-WEB-007: Templates and assets
The system SHALL render pages with `html/template` from a base `layout.html` and one page template per feature file in `internal/web`, all embedded and parsed at startup; a template that fails to parse, lacks a `content` block, or a missing `layout.html` or `error.html` SHALL make `web.New` fail. The system SHALL serve one embedded CSS file (`/static/app.css`) and embedded htmx (`/static/htmx.min.js`) and SHALL reference no external resources.

### REQ-WEB-008: Security headers
The system SHALL send on every response `Content-Security-Policy` without `unsafe-inline`, `unsafe-eval` or external sources (`default-src 'none'; script-src 'self'; style-src 'self'; ... frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: same-origin`, including error pages and redirects.

### REQ-WEB-009: Dashboard and health
The system SHALL serve a placeholder dashboard at `GET /` to any signed-in user showing the username and role, render unknown paths as a 404 HTML error page, and keep `GET /healthz` public. `asi serve` SHALL wire the store, keyring, `auth.Service` and `web.New`.

