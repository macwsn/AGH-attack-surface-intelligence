//go:build integration

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"asi/internal/store"
)

func auditRowsAfter(t *testing.T, st *store.Store, id int64) []string {
	t.Helper()
	rows, err := st.Pool.Query(context.Background(),
		`SELECT actor || ' ' || action || ' ' || target || ' ' || address FROM audit_log WHERE id > $1 ORDER BY id`, id)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func maxAuditID(t *testing.T, st *store.Store) int64 {
	t.Helper()
	var id int64
	if err := st.Pool.QueryRow(context.Background(), `SELECT coalesce(max(id), 0) FROM audit_log`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// REQ-EXCHANGE-009
func TestCLIChangesAreAudited(t *testing.T) {
	env, _, st := userCreateEnv(t)
	file := filepath.Join(t.TempDir(), "hosts.csv")
	if err := os.WriteFile(file, []byte("address,port,protocol,state,service\n10.7.0.1,22,tcp,open,ssh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		code int
		want []string
	}{
		{"import dry run", []string{"import", "--format", "csv", "--file", file, "--name", "cli-dry", "--dry-run"}, 0, nil},
		{"import", []string{"import", "--format", "csv", "--file", file, "--name", "cli-1"}, 0, []string{"cli import cli-1 local"}},
		{"host edit", []string{"host", "edit", "10.7.0.1", "--add-tag", "dmz", "--notes", "audited"}, 0, []string{"cli host.edit 10.7.0.1 local"}},
		{"host edit unknown host", []string{"host", "edit", "10.7.0.9", "--add-tag", "dmz"}, 1, nil},
	}
	for _, tc := range cases {
		mark := maxAuditID(t, st)
		code, stdout, stderr := runCLI(env, tc.args...)
		if code != tc.code {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q", tc.name, code, stdout, stderr)
		}
		if got := auditRowsAfter(t, st, mark); strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Fatalf("%s: audit rows %q, want %q (exit %d, stderr %q)", tc.name, got, tc.want, code, stderr)
		}
	}
}
