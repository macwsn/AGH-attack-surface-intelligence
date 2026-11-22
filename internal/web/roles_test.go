package web

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"asi/internal/auth"
)

// REQ-WEB-030
func TestRoleProblemMessages(t *testing.T) {
	cases := []struct {
		err    error
		status int
		want   string
	}{
		{fmt.Errorf("x: %w", auth.ErrBuiltinRole), http.StatusConflict, `"r" is a built-in role`},
		{auth.ErrRoleExists, http.StatusConflict, `Role "r" already exists.`},
		{auth.ErrRoleInUse, http.StatusConflict, `role "r" is assigned to a user`},
		{fmt.Errorf("%w: %q", auth.ErrUnknownPermission, "p"), http.StatusUnprocessableEntity, `unknown permission: "p"`},
		{errEmptyRoleName, http.StatusUnprocessableEntity, "Enter a role name."},
		{auth.ErrUnknownRole, http.StatusNotFound, "This role does not exist."},
	}
	for _, tc := range cases {
		status, msg := roleProblem(tc.err, "r")
		if status != tc.status || !strings.Contains(msg, tc.want) {
			t.Errorf("roleProblem(%v) = %d %q, want %d containing %q", tc.err, status, msg, tc.status, tc.want)
		}
	}
	if status, _ := roleProblem(fmt.Errorf("db down"), "r"); status != 0 {
		t.Errorf("unexpected error mapped to %d", status)
	}
}

// REQ-WEB-032
func TestRolesRoutesWithoutService(t *testing.T) {
	r, fa := newTestRouter(t)
	if rec := do(r, http.MethodGet, "/roles", nil, fa.session(t, "alice")); rec.Code != http.StatusInternalServerError {
		t.Fatalf("GET /roles without a role service = %d, want 500", rec.Code)
	}
	if rec := do(r, http.MethodGet, "/roles", nil, fa.session(t, "victor")); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer GET /roles = %d, want 403", rec.Code)
	}
}
