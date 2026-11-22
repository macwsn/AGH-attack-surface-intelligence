//go:build integration

package main

import (
	"context"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/store"
)

func cliAuditRows(t *testing.T, st *store.Store) []string {
	t.Helper()
	rows, err := st.Pool.Query(context.Background(), `SELECT action || ':' || target FROM audit_log WHERE actor = 'cli' AND address = 'local' ORDER BY id`)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		out = append(out, s)
	}
	return out
}

func parseRoleList(t *testing.T, stdout string) map[string]string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) == 0 || strings.Join(strings.Fields(lines[0]), " ") != "ROLE BUILTIN PERMISSIONS" {
		t.Fatalf("role list header missing: %q", stdout)
	}
	roles := map[string]string{}
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) != 3 {
			t.Fatalf("role list line %q: want 3 columns", l)
		}
		roles[f[0]] = f[1] + " " + f[2]
	}
	return roles
}

// REQ-AUTH-021
func TestUserAdminCommands(t *testing.T) {
	env, svc, st := userCreateEnv(t)
	ctx := context.Background()
	setup := auth.Actor{Username: "setup", Addr: "test"}
	for _, u := range [][2]string{{"root", auth.RoleAdmin}, {"alice", auth.RoleViewer}} {
		if err := svc.CreateUser(ctx, setup, u[0], "correct-horse-battery", u[1]); err != nil {
			t.Fatalf("CreateUser(%s): %v", u[0], err)
		}
	}

	code, stdout, stderr := runCLI(env, "user", "list")
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if code != 0 || stderr != "" || len(lines) != 3 || !strings.HasPrefix(lines[0], "USERNAME") ||
		!strings.HasPrefix(strings.Join(strings.Fields(lines[1]), " "), "alice viewer enabled ") ||
		!strings.HasPrefix(strings.Join(strings.Fields(lines[2]), " "), "root admin enabled ") {
		t.Fatalf("user list: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	code, stdout, stderr = runCLI(env, "role", "list")
	roles := parseRoleList(t, stdout)
	if code != 0 || stderr != "" || roles["viewer"] != "true inventory.read" ||
		roles["admin"] != "true export,import,inventory.create,inventory.delete,inventory.edit,inventory.read,role.manage,scan.configure,scan.run,signature.manage,user.manage" ||
		len(roles) != 4 {
		t.Fatalf("role list: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if err := svc.CreateRole(ctx, setup, "auditor", []auth.Permission{auth.PermInventoryRead, auth.PermExport}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if code, stdout, _ = runCLI(env, "role", "list"); code != 0 || parseRoleList(t, stdout)["auditor"] != "false export,inventory.read" {
		t.Fatalf("role list with custom role: exit %d, stdout %q", code, stdout)
	}

	if len(cliAuditRows(t, st)) != 0 {
		t.Fatal("list commands wrote audit rows")
	}

	code, stdout, stderr = runCLI(env, "user", "set-role", "--username", "alice", "--role", "auditor")
	if code != 0 || stdout != "user alice now has role auditor\n" || stderr != "" {
		t.Fatalf("set-role: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if u, err := svc.GetUser(ctx, "alice"); err != nil || u.Role != "auditor" {
		t.Fatalf("alice after set-role = %+v, %v", u, err)
	}

	rejected := []struct {
		args []string
		want string
	}{
		{[]string{"user", "set-role", "--username", "alice", "--role", "superuser"}, `asi user: unknown role: "superuser"`},
		{[]string{"user", "set-role", "--username", "ghost", "--role", "viewer"}, `asi user: unknown user: "ghost"`},
		{[]string{"user", "set-role", "--username", "root", "--role", "viewer"}, "asi user: " + auth.ErrLastAdmin.Error()},
		{[]string{"user", "delete", "--username", "root"}, "asi user: " + auth.ErrLastAdmin.Error()},
		{[]string{"user", "delete", "--username", "ghost"}, `asi user: unknown user: "ghost"`},
	}
	for _, tc := range rejected {
		code, stdout, stderr := runCLI(env, tc.args...)
		if code != 1 || stdout != "" || stderr != tc.want+"\n" {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q; want exit 1 and %q", tc.args, code, stdout, stderr, tc.want)
		}
	}
	if u, err := svc.GetUser(ctx, "root"); err != nil || u.Role != auth.RoleAdmin {
		t.Fatalf("root after rejected changes = %+v, %v", u, err)
	}

	code, stdout, stderr = runCLI(env, "user", "delete", "--username", "alice")
	if code != 0 || stdout != "user alice deleted\n" || stderr != "" {
		t.Fatalf("delete: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if _, err := svc.GetUser(ctx, "alice"); err == nil {
		t.Fatal("alice still exists after delete")
	}

	if got := strings.Join(cliAuditRows(t, st), " "); got != "user.update:alice user.delete:alice" {
		t.Fatalf("cli audit rows = %q, want one per successful change", got)
	}
}
