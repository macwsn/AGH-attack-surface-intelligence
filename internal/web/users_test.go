package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"asi/internal/auth"
)

// REQ-WEB-028
func TestUserProblemMessages(t *testing.T) {
	cases := []struct {
		err    error
		status int
		want   string
	}{
		{fmt.Errorf("wrapped: %w", auth.ErrLastAdmin), http.StatusConflict, `"root" is the last enabled admin`},
		{auth.ErrUserExists, http.StatusConflict, `User "root" already exists.`},
		{auth.ErrPasswordTooShort, http.StatusUnprocessableEntity, "at least 12 characters"},
		{auth.ErrUnknownRole, http.StatusUnprocessableEntity, `role "boss" does not exist`},
		{auth.ErrUnknownUser, http.StatusNotFound, "This user does not exist."},
	}
	for _, tc := range cases {
		status, msg := userProblem(tc.err, "root", "boss")
		if status != tc.status || !strings.Contains(msg, tc.want) {
			t.Errorf("userProblem(%v) = %d %q, want %d containing %q", tc.err, status, msg, tc.status, tc.want)
		}
	}
	if status, _ := userProblem(fmt.Errorf("db down"), "root", ""); status != 0 {
		t.Errorf("unexpected error mapped to %d, want 0 (server error)", status)
	}
}

// REQ-WEB-029
func TestUsersRoutesWithoutService(t *testing.T) {
	r, fa := newTestRouter(t)
	alice := fa.session(t, "alice")
	if rec := do(r, http.MethodGet, "/users/", nil, alice); rec.Code != http.StatusInternalServerError {
		t.Fatalf("GET /users/ without a user service = %d, want 500", rec.Code)
	}
	if rec := do(r, http.MethodGet, "/users", nil, alice); rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Location") != "/users/" {
		t.Fatalf("GET /users = %d %q, want a redirect to /users/", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do(r, http.MethodPost, "/users/bob/disable", url.Values{auth.CSRFFormField: {"csrf-victor"}}, fa.session(t, "victor")); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST = %d, want 403", rec.Code)
	}
}
