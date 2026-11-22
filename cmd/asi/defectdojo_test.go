package main

import (
	"strings"
	"testing"
)

// REQ-DEFECTDOJO-006
func TestDefectDojoUsage(t *testing.T) {
	for _, args := range [][]string{
		{"defectdojo"},
		{"defectdojo", "frob"},
		{"defectdojo", "export"},
		{"defectdojo", "export", "--dry-run"},
		{"defectdojo", "export", "--run", "r", "extra"},
		{"defectdojo", "test", "extra"},
		{"defectdojo", "configure", "--url", "https://dojo.example", "--product", "1"},
		{"defectdojo", "configure", "--product", "1", "--engagement", "2"},
	} {
		code, stdout, stderr := runCLI(unreachableEnv, args...)
		if code != 2 || stdout != "" {
			t.Fatalf("%v: exit %d, stdout %q; want 2", args, code, stdout)
		}
		assertUsage(t, stderr)
	}
	code, _, stderr := runCLI(unreachableEnv, "defectdojo", "export", "--run", "r", "--out", "dir")
	if code != 1 || !strings.Contains(stderr, "--out is only used with --dry-run") {
		t.Fatalf("--out without --dry-run: exit %d stderr %q", code, stderr)
	}
	code, stdout, _ := runCLI(unreachableEnv, "--help")
	if code != 0 || !strings.Contains(stdout, "defectdojo export --run NAME [--dry-run") {
		t.Fatalf("help: %q", stdout)
	}
}
