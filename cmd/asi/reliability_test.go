package main

import (
	"strings"
	"testing"
	"time"

	"asi/internal/scan/nmap/nmaptest"
)

func TestScanRunRefusesTargetSetAboveMaxAddresses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets string
		extra   []string
		count   string
	}{
		{name: "default bound", targets: "10.0.0.0/8\n", count: "16777216"},
		{name: "explicit bound", targets: "192.0.2.0/29\n", extra: []string{"--max-addresses", "4"}, count: "8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &nmaptest.Runner{}
			args := append([]string{"scan", "run", "--targets-file", writeFile(t, "targets.txt", tc.targets), "--ports", "80", "--name", "big", "--wait"}, tc.extra...)
			start := time.Now()
			code, stdout, stderr := runFake(r, unreachableEnv, args...)
			if code == 0 || code == 2 || stdout != "" {
				t.Fatalf("exit %d, stdout %q, stderr %q; want a one-line refusal", code, stdout, stderr)
			}
			if strings.Count(stderr, "\n") != 1 || !strings.Contains(stderr, "--max-addresses") || !strings.Contains(stderr, tc.count) {
				t.Fatalf("stderr %q, want one line naming the count %s and --max-addresses", stderr, tc.count)
			}
			if strings.Contains(stderr, "hunter2") || strings.Contains(stderr, "connect") || time.Since(start) > time.Second {
				t.Fatalf("database contacted before refusing: %q", stderr)
			}
			if calls := r.Calls(); len(calls) != 0 {
				t.Fatalf("nmap called: %+v", calls)
			}
		})
	}
}
