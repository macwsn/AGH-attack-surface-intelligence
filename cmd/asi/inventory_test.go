package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asi/internal/scan/nmap/nmaptest"
)

var unreachableEnv = map[string]string{
	"ASI_DATABASE_URL": "postgres://asi:hunter2@127.0.0.1:1/asi?sslmode=disable&connect_timeout=2",
	"ASI_MASTER_KEY":   testKey,
}

func runFake(r *nmaptest.Runner, env map[string]string, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := runWith(context.Background(), scanDeps{runner: r}, args, strings.NewReader(""), &stdout, &stderr, func(k string) string { return env[k] })
	return code, stdout.String(), stderr.String()
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanRunValidation(t *testing.T) {
	targets := writeFile(t, "targets.txt", "192.0.2.0/29\n")
	base := func(extra ...string) []string {
		return append([]string{"scan", "run", "--targets-file", targets, "--name", "v", "--wait"}, extra...)
	}

	r := &nmaptest.Runner{}
	for _, args := range [][]string{
		{"scan"},
		{"scan", "frob"},
		{"scan", "run", "--ports", "80", "--name", "v", "--wait"},
		{"scan", "run", "--targets-file", targets, "--name", "v", "--wait"},
		{"scan", "run", "--targets-file", targets, "--ports", "80", "--wait"},
		{"scan", "run", "--targets-file", targets, "--ports", "80", "--name", "v"},
		{"scan", "run", "--targets-file", targets, "--ports", "80", "--name", "v", "--wait", "extra"},
		{"scan", "show"},
		{"scan", "resume"},
		{"scan", "show", "a", "b"},
	} {
		code, stdout, stderr := runFake(r, unreachableEnv, args...)
		if code != 2 || stdout != "" {
			t.Fatalf("%v: exit %d, stdout %q; want 2", args, code, stdout)
		}
		assertUsage(t, stderr)
	}

	for _, tc := range []struct {
		args []string
		flag string
	}{
		{base("--ports", "80,abc"), "--ports"},
		{base("--ports", "0"), "--ports"},
		{base("--ports", "65536"), "--ports"},
		{base("--ports", ""), "--ports"},
		{base("--ports", "80,"), "--ports"},
		{base("--ports", "21,8100-8000"), `--ports: invalid port range "8100-8000"`},
		{base("--ports", "top1000,1-70000"), `--ports: invalid port range "1-70000"`},
		{base("--ports", "top5"), `--ports: invalid port "top5"`},
		{base("--ports", "80", "--workers", "0"), "--workers"},
		{base("--ports", "80", "--max-rate", "0"), "--max-rate"},
		{base("--ports", "80", "--max-rate", "-5"), "--max-rate"},
		{base("--ports", "80", "--max-rate", "1"), "--max-rate"},
		{base("--ports", "80", "--inactive-after", "0"), "--inactive-after"},
		{base("--ports", "80", "--http-timeout", "0s"), "--http-timeout"},
		{base("--ports", "80", "--service-detection", "full"), "--service-detection"},
		{[]string{"scan", "run", "--targets-file", filepath.Join(t.TempDir(), "missing.txt"), "--ports", "80", "--name", "v", "--wait"}, "--targets-file"},
		{[]string{"scan", "run", "--targets-file", writeFile(t, "bad.txt", "not a target!\n"), "--ports", "80", "--name", "v", "--wait"}, "--targets-file"},
		{base("--ports", "80", "--exclude-file", writeFile(t, "ex.txt", "10.0.0.0/99\n")), "--exclude-file"},
		{base("--ports", "80", "--signatures-dir", writeFile(t, "sigs", "")), "--signatures-dir"},
	} {
		start := time.Now()
		code, stdout, stderr := runFake(r, unreachableEnv, tc.args...)
		if code == 0 || code == 2 || stdout != "" {
			t.Fatalf("%v: exit %d, stdout %q", tc.args, code, stdout)
		}
		if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, "asi scan: ") || !strings.Contains(stderr, tc.flag) {
			t.Fatalf("%v: stderr %q, want one line naming %s", tc.args, stderr, tc.flag)
		}
		if strings.Contains(stderr, "hunter2") || strings.Contains(stderr, "connect") || time.Since(start) > time.Second {
			t.Fatalf("%v: database contacted: %q", tc.args, stderr)
		}
	}
	if calls := r.Calls(); len(calls) != 0 {
		t.Fatalf("nmap called during validation: %+v", calls)
	}
}

func TestInventoryCommandUsage(t *testing.T) {
	for _, args := range [][]string{
		{"export", "--out", "x.json"},
		{"export", "--format", "json"},
		{"export", "--format", "json", "--out", "x.json", "extra"},
		{"diff", "--to", "b", "--out", "x.json"},
		{"diff", "--from", "a", "--out", "x.json"},
		{"diff", "--from", "a", "--to", "b"},
		{"host"},
		{"host", "edit"},
		{"host", "edit", "--add-tag", "x"},
		{"host", "edit", "192.0.2.1", "192.0.2.2"},
		{"host", "frob", "192.0.2.1"},
	} {
		code, stdout, stderr := runCLI(unreachableEnv, args...)
		if code != 2 || stdout != "" {
			t.Fatalf("%v: exit %d, stdout %q; want 2", args, code, stdout)
		}
		assertUsage(t, stderr)
	}

	out := filepath.Join(t.TempDir(), "out")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"export", "--format", "xml", "--out", out}, "--format"},
		{[]string{"diff", "--from", "a", "--to", "b", "--format", "csv", "--out", out}, "--format"},
		{[]string{"host", "edit", "not-an-ip", "--add-tag", "x"}, "invalid address"},
		{[]string{"host", "edit", "192.0.2.1", "--add-tag", ""}, "non-empty tag"},
	} {
		code, stdout, stderr := runCLI(unreachableEnv, tc.args...)
		if code == 0 || code == 2 || stdout != "" || strings.Count(stderr, "\n") != 1 || !strings.Contains(stderr, tc.want) {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q", tc.args, code, stdout, stderr)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%v: output file created", tc.args)
		}
	}
}
