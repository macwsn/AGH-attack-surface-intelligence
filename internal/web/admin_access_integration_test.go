//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"asi/internal/auth"
)

var adminNav = []string{`<a href="/users/">Users</a>`, `<a href="/roles">Roles</a>`, `<a href="/audit">Audit log</a>`}

// REQ-WEB-035
func TestAdministrationAndDeleteRoutesForbiddenToViewer(t *testing.T) {
	e, _ := newAuditEnv(t)
	r := e.h.(*Router)
	values := strings.NewReplacer("{username}", auth.RoleAdmin, "{name}", auth.RoleOperator, "{address}", "10.0.0.1",
		"{port}", "22", "{protocol}", "tcp", "{$}", "", "{id}", "1")
	var routes []string
	for _, rt := range r.Routes() {
		if !strings.HasPrefix(rt.Path, "/users") && !strings.HasPrefix(rt.Path, "/roles") && !strings.HasPrefix(rt.Path, "/audit") &&
			!strings.HasSuffix(rt.Path, "/delete") {
			continue
		}
		routes = append(routes, rt.Method+" "+rt.Path)
		target := values.Replace(rt.Path)
		var code int
		if rt.Method == http.MethodGet {
			code, _ = e.get(auth.RoleViewer, target)
		} else {
			code, _, _ = e.post(auth.RoleViewer, target, url.Values{"role": {auth.RoleViewer}, "name": {"x"}, "perm": {"user.manage"},
				"username": {"x"}, "password": {"viewer-takes-over-1"}})
		}
		if code != http.StatusForbidden {
			t.Errorf("viewer %s %s = %d, want 403", rt.Method, target, code)
		}
	}
	for _, want := range []string{"GET /users/{$}", "POST /users/{username}/delete", "GET /roles", "POST /roles/{name}/delete", "GET /audit",
		"POST /hosts/{address}/delete", "POST /hosts/{address}/services/{port}/{protocol}/delete", "POST /scans/{id}/delete"} {
		if !slices.Contains(routes, want) {
			t.Errorf("route %s is not registered", want)
		}
	}
	if len(routes) != 21 {
		t.Errorf("checked %d routes, want 8 users + 5 roles + 1 audit + 4 host/service delete + 2 scan delete + 1 signature delete:\n%s", len(routes), strings.Join(routes, "\n"))
	}
	if u, err := e.svc.GetUser(context.Background(), auth.RoleAdmin); err != nil || u.Role != auth.RoleAdmin || u.Disabled {
		t.Fatalf("admin changed by viewer requests: %+v %v", u, err)
	}
	if r, ok := e.role(t, auth.RoleOperator); !ok || len(r.Permissions) != 3 {
		t.Fatalf("operator role changed by viewer requests: %+v", r)
	}
}

// REQ-WEB-035
func TestAdministrationNavByPermission(t *testing.T) {
	e, _ := newAuditEnv(t)
	ctx := context.Background()
	for name, perms := range map[string][]auth.Permission{
		"accounts": {auth.PermUserManage},
		"rbac":     {auth.PermRoleManage},
	} {
		if err := e.svc.CreateRole(ctx, auth.Actor{Username: "setup"}, name, perms); err != nil {
			t.Fatal(err)
		}
		e.addSession(t, name+"-user", name)
	}
	cases := []struct {
		user string
		want []bool
	}{
		{auth.RoleAdmin, []bool{true, true, true}},
		{auth.RoleEditor, []bool{false, false, false}},
		{auth.RoleOperator, []bool{false, false, false}},
		{auth.RoleViewer, []bool{false, false, false}},
		{"accounts-user", []bool{true, false, true}},
		{"rbac-user", []bool{false, true, false}},
	}
	for _, tc := range cases {
		_, page := e.get(tc.user, "/")
		nav := regexp.MustCompile(`(?s)<nav aria-label="Main">.*?</nav>`).FindString(page)
		for i, entry := range adminNav {
			if strings.Contains(nav, entry) != tc.want[i] {
				t.Errorf("%s: nav entry %s shown = %v, want %v", tc.user, entry, !tc.want[i], tc.want[i])
			}
		}
		if heading := strings.Contains(nav, `<h2 class="nav-heading">Administration</h2>`); heading != slices.Contains(tc.want, true) {
			t.Errorf("%s: Administration heading shown = %v", tc.user, heading)
		}
		for i, path := range []string{"/users/", "/roles", "/audit"} {
			code, body := e.get(tc.user, path)
			if (code == http.StatusOK) != tc.want[i] {
				t.Errorf("%s GET %s = %d", tc.user, path, code)
			}
			if code == http.StatusOK && (strings.Contains(body, "style=") || strings.Contains(body, "<style")) {
				t.Errorf("%s has inline styles", path)
			}
		}
	}
}
