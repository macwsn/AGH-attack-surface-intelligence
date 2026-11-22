//go:build integration

package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"asi/internal/auth"
)

func (e *usersEnv) passwordHash(t *testing.T, username string) string {
	t.Helper()
	var hash string
	if err := e.st.Pool.QueryRow(context.Background(), `SELECT password_hash FROM users WHERE username = $1`, username).Scan(&hash); err != nil {
		t.Fatalf("password hash of %s: %v", username, err)
	}
	return hash
}

func (e *usersEnv) auditRowsAfter(t *testing.T, id int64) string {
	t.Helper()
	var all string
	if err := e.st.Pool.QueryRow(context.Background(),
		`SELECT coalesce(string_agg(a::text, ' '), '') FROM audit_log a WHERE id > $1`, id).Scan(&all); err != nil {
		t.Fatalf("audit rows: %v", err)
	}
	return all
}

// REQ-WEB-040
func TestAccountPageForEveryRole(t *testing.T) {
	e := newUsersEnv(t)
	for _, role := range []string{auth.RoleAdmin, auth.RoleEditor, auth.RoleOperator, auth.RoleViewer} {
		code, body := e.get(role, "/account")
		if code != http.StatusOK {
			t.Fatalf("%s GET /account = %d", role, code)
		}
		for _, want := range []string{"<h1>Your account</h1>", "<dt>Username</dt><dd>" + role + "</dd>", "<dt>Role</dt><dd>" + role + "</dd>",
			`<form method="post" action="/account/password">`, `name="current_password"`, `name="password"`, `name="repeat"`,
			`<a class="who" href="/account">` + role + `</a>`, `name="` + auth.CSRFFormField + `"`} {
			if !strings.Contains(body, want) {
				t.Fatalf("%s account page lacks %q:\n%s", role, want, body)
			}
		}
		if regexp.MustCompile(`style\s*=|<style`).MatchString(body) {
			t.Fatalf("%s account page has an inline style", role)
		}
		checkPageIsSafe(t, "account page", body)
		if _, home := e.get(role, "/"); !strings.Contains(home, `<a class="who" href="/account">`+role+`</a>`) {
			t.Fatalf("%s: the user name in the rail does not link to /account", role)
		}
	}
	r := e.h.(*Router)
	found := map[string]bool{}
	for _, rt := range r.Routes() {
		if strings.HasPrefix(rt.Path, "/account") {
			found[rt.Method+" "+rt.Path] = true
			if rt.Access.String() != "signed-in" {
				t.Errorf("%s %s access = %s, want signed-in", rt.Method, rt.Path, rt.Access)
			}
		}
	}
	if len(found) != 2 || !found["GET /account"] || !found["POST /account/password"] {
		t.Fatalf("account routes = %v", found)
	}
	rec := do(e.h, http.MethodGet, "/account", nil)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
		t.Fatalf("GET /account without a session = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// REQ-WEB-041 REQ-AUTH-023
func TestViewerChangesOwnPassword(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	const newPass = "viewer-new-password-7"
	other, err := e.svc.Login(ctx, auth.RoleViewer, userPassword, "local")
	if err != nil {
		t.Fatalf("second viewer login: %v", err)
	}
	otherCookie := &http.Cookie{Name: auth.SessionCookieName, Value: other.Token}
	mark := e.lastAudit(t)
	code, loc, body := e.post(auth.RoleViewer, "/account/password",
		url.Values{"current_password": {userPassword}, "password": {newPass}, "repeat": {newPass}})
	if code != http.StatusSeeOther || loc != "/account?done=password" {
		t.Fatalf("change password = %d %q\n%s", code, loc, body)
	}
	if got := e.auditAfter(t, mark); len(got) != 1 || got[0] != "viewer user.password viewer 192.0.2.1" {
		t.Fatalf("audit rows %q, want one user.password by viewer for viewer", got)
	}
	if all := e.auditRowsAfter(t, mark); strings.Contains(all, newPass) || strings.Contains(all, userPassword) || strings.Contains(all, "argon2") {
		t.Fatalf("audit row contains password material: %s", all)
	}
	if hash := e.passwordHash(t, auth.RoleViewer); !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("stored hash %q is not argon2id", hash)
	}
	code, page := e.get(auth.RoleViewer, loc)
	if code != http.StatusOK || !strings.Contains(page, `<div class="notice ok" role="status">Password changed. Your other sessions have ended.</div>`) {
		t.Fatalf("confirmation after redirect = %d:\n%s", code, page)
	}
	rec := do(e.h, http.MethodGet, "/hosts/", nil, otherCookie)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
		t.Fatalf("other session of the viewer still valid: GET /hosts/ = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if code, _ := e.get(auth.RoleViewer, "/hosts/"); code != http.StatusOK {
		t.Fatalf("current session ended by the change: GET /hosts/ = %d", code)
	}
	if code, _ := e.get(auth.RoleEditor, "/hosts/"); code != http.StatusOK {
		t.Fatalf("another user's session ended: GET /hosts/ = %d", code)
	}
	if err := e.login(auth.RoleViewer, userPassword); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("old password after change: %v, want invalid credentials", err)
	}
	if err := e.login(auth.RoleViewer, newPass); err != nil {
		t.Fatalf("new password does not work: %v", err)
	}
}

// REQ-WEB-041 REQ-AUTH-023
func TestOwnPasswordChangeProblems(t *testing.T) {
	e := newUsersEnv(t)
	const good = "operator-new-pass-1"
	cases := []struct {
		name   string
		form   url.Values
		status int
		field  string
		want   string
	}{
		{"wrong current", url.Values{"current_password": {"not-the-password"}, "password": {good}, "repeat": {good}},
			http.StatusUnprocessableEntity, "current_password", "The current password is wrong. Nothing was changed."},
		{"short", url.Values{"current_password": {userPassword}, "password": {"short-pass"}, "repeat": {"short-pass"}},
			http.StatusUnprocessableEntity, "password", "The new password must be at least 12 characters."},
		{"mismatch", url.Values{"current_password": {userPassword}, "password": {good}, "repeat": {good + "x"}},
			http.StatusUnprocessableEntity, "repeat", "The two new passwords do not match. Type the same password twice."},
		{"same as current", url.Values{"current_password": {userPassword}, "password": {userPassword}, "repeat": {userPassword}},
			http.StatusUnprocessableEntity, "password", "The new password must differ from the current one."},
	}
	before := e.passwordHash(t, auth.RoleOperator)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mark := e.lastAudit(t)
			code, _, body := e.post(auth.RoleOperator, "/account/password", tc.form)
			if code != tc.status {
				t.Fatalf("%d, want %d:\n%s", code, tc.status, body)
			}
			next := regexp.MustCompile(`name="` + tc.field + `"[^>]*aria-invalid="true"><span class="problem">` + regexp.QuoteMeta(tc.want) + `</span>`)
			if !next.MatchString(body) {
				t.Fatalf("message %q is not next to field %s:\n%s", tc.want, tc.field, body)
			}
			if n := strings.Count(body, `class="problem"`); n != 1 {
				t.Fatalf("%d field messages, want 1", n)
			}
			if after := e.passwordHash(t, auth.RoleOperator); after != before {
				t.Fatal("rejected change replaced the password hash")
			}
			for _, row := range e.auditAfter(t, mark) {
				if strings.Contains(row, "user.password") {
					t.Fatalf("rejected change wrote %q", row)
				}
			}
		})
	}
	if code, _ := e.get(auth.RoleOperator, "/hosts/"); code != http.StatusOK {
		t.Fatalf("session ended by rejected changes: %d", code)
	}
	if code, _, _ := (&usersEnv{h: e.h, cookies: e.cookies, csrf: map[string]string{}}).post(auth.RoleOperator, "/account/password",
		url.Values{"current_password": {userPassword}, "password": {good}, "repeat": {good}}); code != http.StatusForbidden {
		t.Fatalf("POST without CSRF token = %d, want 403", code)
	}
	if after := e.passwordHash(t, auth.RoleOperator); after != before {
		t.Fatal("request without CSRF token changed the password")
	}
}

// REQ-AUTH-023
func TestWrongCurrentPasswordCountsTowardLoginThrottle(t *testing.T) {
	e := newUsersEnv(t)
	const good = "editor-new-pass-12"
	before := e.passwordHash(t, auth.RoleEditor)
	form := url.Values{"current_password": {"not-the-password"}, "password": {good}, "repeat": {good}}
	for i := 0; i < auth.DefaultAccountLimit; i++ {
		if code, _, _ := e.post(auth.RoleEditor, "/account/password", form); code != http.StatusUnprocessableEntity {
			t.Fatalf("wrong current password #%d = %d, want 422", i+1, code)
		}
	}
	if err := e.login(auth.RoleEditor, userPassword); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("login after %d wrong current passwords: %v, want rate limited", auth.DefaultAccountLimit, err)
	}
	code, _, body := e.post(auth.RoleEditor, "/account/password", url.Values{"current_password": {userPassword}, "password": {good}, "repeat": {good}})
	if code != http.StatusTooManyRequests || !strings.Contains(body, `<span class="problem">Too many wrong passwords. Wait a few minutes and try again.</span>`) {
		t.Fatalf("change with the right password while throttled = %d:\n%s", code, body)
	}
	if after := e.passwordHash(t, auth.RoleEditor); after != before {
		t.Fatal("throttled request changed the password")
	}
}

// REQ-WEB-028
func TestUsersCreateFormProblemsNextToField(t *testing.T) {
	e := newUsersEnv(t)
	cases := []struct {
		name  string
		form  url.Values
		field string
		want  string
	}{
		{"duplicate user", url.Values{"username": {"viewer"}, "role": {auth.RoleViewer}, "password": {userPassword}},
			"username", `User &#34;viewer&#34; already exists. Choose another username.`},
		{"short password", url.Values{"username": {"erin"}, "role": {auth.RoleViewer}, "password": {"short"}},
			"password", "Nothing was changed: the password must be at least 12 characters."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, body := e.post(auth.RoleAdmin, "/users/create", tc.form)
			next := regexp.MustCompile(`name="` + tc.field + `"[^>]*aria-invalid="true"><span class="problem">` + regexp.QuoteMeta(tc.want) + `</span>`)
			if !next.MatchString(body) {
				t.Fatalf("message %q is not next to field %s:\n%s", tc.want, tc.field, body)
			}
		})
	}
	if _, body := e.get(auth.RoleAdmin, "/users/"); !strings.Contains(body, `<p class="lede">4 users, 0 disabled.`) {
		t.Fatalf("users header does not count 4 users:\n%s", body)
	}
}
