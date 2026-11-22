package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"asi/internal/scan/nmap/nmaptest"
)

// REQ-SCAN-016
func TestScanRunModeRejected(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targets, []byte("192.0.2.0/29\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &nmaptest.Runner{}
	env := map[string]string{"ASI_DATABASE_URL": "postgres://asi:x@127.0.0.1:1/asi", "ASI_MASTER_KEY": testKey}
	for _, mode := range []string{"fast", "", "FULL"} {
		var stdout, stderr bytes.Buffer
		code := runWith(context.Background(), scanDeps{runner: r}, []string{"scan", "run", "--targets-file", targets, "--ports", "80",
			"--name", "m", "--mode", mode, "--wait"}, strings.NewReader(""), &stdout, &stderr, func(k string) string { return env[k] })
		if code != 1 || strings.Count(stderr.String(), "\n") != 1 || !strings.Contains(stderr.String(), "--mode") ||
			!strings.Contains(stderr.String(), "full|recheck") {
			t.Fatalf("--mode %q: exit %d, stderr %q", mode, code, stderr.String())
		}
		if strings.Contains(stderr.String(), "connect") || stdout.Len() != 0 {
			t.Fatalf("--mode %q reached the database: stdout %q, stderr %q", mode, stdout.String(), stderr.String())
		}
	}
	if n := len(r.Calls()); n != 0 {
		t.Fatalf("%d nmap calls, want 0", n)
	}
	var stdout bytes.Buffer
	if code := runWith(context.Background(), scanDeps{runner: r}, []string{"help"}, strings.NewReader(""), &stdout, &bytes.Buffer{}, func(string) string { return "" }); code != 0 ||
		!strings.Contains(stdout.String(), "[--mode full|recheck]") {
		t.Fatalf("usage does not list --mode: %q", stdout.String())
	}
}
