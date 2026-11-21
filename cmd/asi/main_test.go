package main

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var contractCommands = []string{"migrate", "serve", "user", "scan", "export", "diff", "import", "host"}

const testKey = "bGFiLW9ubHkta2V5LWxhYi1vbmx5LWtleS1sYWItMDE="

func runCLI(env map[string]string, args ...string) (int, string, string) {
	return runCLIStdin(env, "", args...)
}

func runCLIStdin(env map[string]string, stdin string, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, strings.NewReader(stdin), &stdout, &stderr, func(k string) string { return env[k] })
	return code, stdout.String(), stderr.String()
}

func assertUsage(t *testing.T, out string) {
	t.Helper()
	for _, c := range contractCommands {
		if !strings.Contains(out, "\n  "+c+" ") {
			t.Errorf("usage does not list %q:\n%s", c, out)
		}
	}
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}, {"migrate", "--help"}} {
		code, stdout, _ := runCLI(nil, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d, want 0", args, code)
		}
		assertUsage(t, stdout)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, stdout, stderr := runCLI(nil, "frobnicate")
	if code == 0 {
		t.Fatal("unknown command exited 0")
	}
	if stdout != "" {
		t.Fatalf("unexpected stdout %q", stdout)
	}
	if !strings.HasPrefix(stderr, `asi: unknown command "frobnicate"`) {
		t.Fatalf("stderr = %q", stderr)
	}
	assertUsage(t, stderr)
}

func TestNoArgs(t *testing.T) {
	code, _, stderr := runCLI(nil)
	if code == 0 {
		t.Fatal("no command exited 0")
	}
	assertUsage(t, stderr)
}

func TestVersion(t *testing.T) {
	code, stdout, _ := runCLI(nil, "version")
	if code != 0 || !strings.HasPrefix(stdout, "asi ") {
		t.Fatalf("version: exit %d, stdout %q", code, stdout)
	}
}

func TestConfigErrors(t *testing.T) {
	goodURL := "postgres://asi:hunter2@127.0.0.1:1/asi?sslmode=disable"
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"missing url", map[string]string{"ASI_MASTER_KEY": testKey}, "ASI_DATABASE_URL is not set"},
		{"malformed url", map[string]string{"ASI_DATABASE_URL": "postgres://asi:hunter2@host:port/db", "ASI_MASTER_KEY": testKey}, "ASI_DATABASE_URL is malformed"},
		{"missing key", map[string]string{"ASI_DATABASE_URL": goodURL}, "ASI_MASTER_KEY is not set"},
		{"malformed key", map[string]string{"ASI_DATABASE_URL": goodURL, "ASI_MASTER_KEY": "c2hvcnQ="}, "ASI_MASTER_KEY is malformed"},
	}
	for _, cmd := range []string{"migrate", "serve"} {
		for _, tc := range cases {
			t.Run(cmd+"/"+tc.name, func(t *testing.T) {
				code, stdout, stderr := runCLI(tc.env, cmd)
				if code == 0 {
					t.Fatal("exit 0, want non-zero")
				}
				if stdout != "" {
					t.Fatalf("unexpected stdout %q", stdout)
				}
				if strings.Count(stderr, "\n") != 1 || !strings.HasSuffix(stderr, "\n") {
					t.Fatalf("stderr is not one line: %q", stderr)
				}
				if !strings.Contains(stderr, tc.want) {
					t.Fatalf("stderr = %q, want %q", stderr, tc.want)
				}
				if strings.Contains(stderr, "hunter2") {
					t.Fatalf("stderr leaks the password: %q", stderr)
				}
			})
		}
	}
}

func TestMigrateUnreachableDatabase(t *testing.T) {
	env := map[string]string{
		"ASI_DATABASE_URL": "postgres://asi:hunter2@127.0.0.1:1/asi?sslmode=disable&connect_timeout=2",
		"ASI_MASTER_KEY":   testKey,
	}
	code, _, stderr := runCLI(env, "migrate")
	if code == 0 {
		t.Fatal("exit 0, want non-zero")
	}
	if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, "asi migrate: ") || strings.Contains(stderr, "hunter2") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestNotImplementedCommand(t *testing.T) {
	env := map[string]string{"ASI_DATABASE_URL": "postgres://asi@127.0.0.1/asi", "ASI_MASTER_KEY": testKey}
	code, _, stderr := runCLI(env, "import", "--format", "json")
	if code == 0 || stderr != "asi import: not implemented yet\n" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "asi")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func TestBinaryConfigErrorExitCode(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "migrate")
	cmd.Env = []string{"ASI_MASTER_KEY=" + testKey}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("err = %v, want exit code 1", err)
	}
	if got := stderr.String(); got != "asi migrate: ASI_DATABASE_URL is not set\n" {
		t.Fatalf("stderr = %q", got)
	}
}

// REQ-AUTH-016
func TestUserCreateUsage(t *testing.T) {
	env := map[string]string{"ASI_DATABASE_URL": "postgres://asi@127.0.0.1:1/asi", "ASI_MASTER_KEY": testKey}
	for _, args := range [][]string{
		{"user"},
		{"user", "frob"},
		{"user", "create", "--role", "admin", "--password-stdin"},
		{"user", "create", "--username", "alice", "--password-stdin"},
		{"user", "create", "--username", "alice", "--role", "admin", "--password-stdin", "extra"},
	} {
		code, stdout, stderr := runCLIStdin(env, "correct-horse-battery\n", args...)
		if code != 2 || stdout != "" {
			t.Fatalf("%v: exit %d, stdout %q; want 2 and no stdout", args, code, stdout)
		}
		assertUsage(t, stderr)
		if !strings.Contains(stderr, "user create --username U --role R [--password-stdin]") {
			t.Fatalf("%v: usage lacks the user create line:\n%s", args, stderr)
		}
	}

	code, stdout, stderr := runCLIStdin(env, "correct-horse-battery\n", "user", "create", "--username", "alice", "--role", "admin")
	if code != 1 || stdout != "" || strings.Count(stderr, "\n") != 1 || !strings.Contains(stderr, "--password-stdin") {
		t.Fatalf("without --password-stdin: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	code, stdout, _ = runCLI(nil, "--help")
	if code != 0 || !strings.Contains(stdout, "  user       user create --username U --role R [--password-stdin]\n") {
		t.Fatalf("--help: exit %d, stdout %q", code, stdout)
	}
}
