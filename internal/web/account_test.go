package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"asi/internal/auth"
)

// REQ-WEB-028
func TestUsersPageCount(t *testing.T) {
	cases := map[int]string{0: "0 users", 1: "1 user", 2: "2 users", 12: "12 users"}
	for n, want := range cases {
		if got := (usersPage{Users: make([]userRow, n)}).Count(); got != want {
			t.Errorf("Count() with %d users = %q, want %q", n, got, want)
		}
	}
}

// REQ-WEB-040 REQ-WEB-041
func TestAccountPageForViewer(t *testing.T) {
	r, fa := newTestRouter(t)
	victor := fa.session(t, "victor")
	rec := do(r, http.MethodGet, "/account", nil, victor)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "<h1>Your account</h1>") || !strings.Contains(body, "<dd>victor</dd>") ||
		!strings.Contains(body, "<dd>"+auth.RoleViewer+"</dd>") {
		t.Fatalf("viewer GET /account = %d:\n%s", rec.Code, body)
	}
	for _, tc := range []struct {
		form  url.Values
		field string
	}{
		{url.Values{"current_password": {"victor-password-1"}, "password": {"short"}, "repeat": {"short"}}, "password"},
		{url.Values{"current_password": {"victor-password-1"}, "password": {"long-enough-pass-1"}, "repeat": {"long-enough-pass-2"}}, "repeat"},
	} {
		tc.form.Set(auth.CSRFFormField, "csrf-victor")
		rec := do(r, http.MethodPost, "/account/password", tc.form, victor)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `name="`+tc.field+`"`) ||
			!strings.Contains(rec.Body.String(), `aria-invalid="true"><span class="problem">`) {
			t.Fatalf("POST %v = %d:\n%s", tc.form, rec.Code, rec.Body.String())
		}
	}
	if rec := do(r, http.MethodPost, "/account/password", url.Values{"password": {"long-enough-pass-1"}}, victor); rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF token = %d, want 403", rec.Code)
	}
}
