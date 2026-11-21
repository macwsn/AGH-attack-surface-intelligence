//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"asi/internal/auth"
	"asi/internal/store"
	"asi/internal/store/storetest"
)

func TestMigrateBinaryTwice(t *testing.T) {
	bin := buildBinary(t)
	dbURL := storetest.DatabaseURL(t)
	env := append(os.Environ(), "ASI_DATABASE_URL="+dbURL, "ASI_MASTER_KEY="+testKey)

	for i, want := range []string{"migrations: applied 0001_settings", "migrations: up to date"} {
		cmd := exec.Command(bin, "migrate")
		cmd.Env = env
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("run %d: %v, stderr %q", i+1, err, stderr.String())
		}
		if !strings.HasPrefix(stdout.String(), want) {
			t.Fatalf("run %d: stdout %q, want prefix %q", i+1, stdout.String(), want)
		}
	}
}

func TestServeHealthz(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	env := map[string]string{"ASI_DATABASE_URL": storetest.DatabaseURL(t), "ASI_MASTER_KEY": testKey, "ASI_LISTEN": addr}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"serve"}, strings.NewReader(""), io.Discard, io.Discard, func(k string) string { return env[k] })
	}()

	var resp *http.Response
	for range 50 {
		resp, err = http.Get(fmt.Sprintf("http://%s/healthz", addr))
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		t.Fatalf("/healthz = %d %q", resp.StatusCode, body)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exited %d after shutdown", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func userCreateEnv(t *testing.T) (map[string]string, *auth.Service, *store.Store) {
	t.Helper()
	ctx := context.Background()
	dbURL := storetest.DatabaseURL(t)
	env := map[string]string{"ASI_DATABASE_URL": dbURL, "ASI_MASTER_KEY": testKey}
	if code, _, stderr := runCLI(env, "migrate"); code != 0 {
		t.Fatalf("migrate: exit %d, stderr %q", code, stderr)
	}
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	return env, auth.NewService(st, auth.Config{}), st
}

func countUsers(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	if err := st.Pool.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

// REQ-AUTH-016
func TestUserCreateBinary(t *testing.T) {
	bin := buildBinary(t)
	env, svc, st := userCreateEnv(t)
	ctx := context.Background()
	osEnv := append(os.Environ(), "ASI_DATABASE_URL="+env["ASI_DATABASE_URL"], "ASI_MASTER_KEY="+testKey)

	runUser := func(username, stdin string) (int, string, string) {
		cmd := exec.Command(bin, "user", "create", "--username", username, "--role", "admin", "--password-stdin")
		cmd.Env = osEnv
		cmd.Stdin = strings.NewReader(stdin)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatalf("run: %v", err)
		}
		return code, stdout.String(), stderr.String()
	}

	code, stdout, stderr := runUser("alice", "correct-horse-battery\n")
	if code != 0 || strings.Count(stdout, "\n") != 1 || !strings.Contains(stdout, "alice") {
		t.Fatalf("user create: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if _, err := svc.Login(ctx, "alice", "correct-horse-battery", "127.0.0.1"); err != nil {
		t.Fatalf("Login after user create: %v", err)
	}
	var n int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'user.create' AND target = 'alice' AND actor = 'cli' AND address = 'local'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audit rows = %d, err %v; want 1", n, err)
	}

	code, stdout, stderr = runUser("alice", "correct-horse-battery\n")
	if code != 1 || stdout != "" || strings.Count(stderr, "\n") != 1 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("duplicate: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	if code, _, stderr = runUser("bob", "correct-horse-battery\r\n"); code != 0 {
		t.Fatalf("CRLF: exit %d, stderr %q", code, stderr)
	}
	if _, err := svc.Login(ctx, "bob", "correct-horse-battery", "127.0.0.1"); err != nil {
		t.Fatalf("Login after CRLF password: %v", err)
	}

	if code, _, stderr = runUser("carol", " correct-horse-battery \n\n"); code != 0 {
		t.Fatalf("spaces: exit %d, stderr %q", code, stderr)
	}
	if _, err := svc.Login(ctx, "carol", " correct-horse-battery ", "127.0.0.1"); err != nil {
		t.Fatalf("Login with surrounding spaces kept: %v", err)
	}
}

func TestUserCreateRejectsShortPassword(t *testing.T) {
	env, _, st := userCreateEnv(t)
	code, stdout, stderr := runCLIStdin(env, "elevenchars\n", "user", "create", "--username", "alice", "--role", "admin", "--password-stdin")
	if code != 1 || stdout != "" || strings.Count(stderr, "\n") != 1 || !strings.Contains(stderr, "12 characters") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if n := countUsers(t, st); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
}

func TestUserCreateUnknownRole(t *testing.T) {
	env, _, st := userCreateEnv(t)
	code, stdout, stderr := runCLIStdin(env, "correct-horse-battery\n", "user", "create", "--username", "alice", "--role", "superuser", "--password-stdin")
	if code != 1 || stdout != "" || strings.Count(stderr, "\n") != 1 || !strings.Contains(stderr, "superuser") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if n := countUsers(t, st); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
}

func TestUserCreateRequiresPasswordStdin(t *testing.T) {
	env, _, st := userCreateEnv(t)
	for _, args := range [][]string{
		{"user", "create", "--username", "alice", "--role", "admin"},
		{"user", "create", "--role", "admin", "--password-stdin"},
		{"user", "create", "--username", "alice", "--password-stdin"},
	} {
		code, _, stderr := runCLIStdin(env, "correct-horse-battery\n", args...)
		if code == 0 || stderr == "" {
			t.Fatalf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	if n := countUsers(t, st); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
}
