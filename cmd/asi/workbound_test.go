package main

import (
	"strings"
	"testing"

	"asi/internal/scan/nmap/nmaptest"
)

func TestScanRunAndPlanRefuseAddressesTimesPortsAboveCeiling(t *testing.T) {
	for _, sub := range []string{"run", "plan"} {
		t.Run(sub, func(t *testing.T) {
			r := &nmaptest.Runner{}
			args := []string{"scan", sub, "--targets-file", writeFile(t, "targets.txt", "10.0.0.0/14\n"), "--ports", "1-1001"}
			if sub == "run" {
				args = append(args, "--name", "wide", "--wait")
			}
			code, stdout, stderr := runFake(r, unreachableEnv, args...)
			if code == 0 || code == 2 || stdout != "" {
				t.Fatalf("262144 addresses x 1001 ports: exit %d, stdout %q, stderr %q; want a refusal", code, stdout, stderr)
			}
			if !strings.Contains(stderr, "26214") || !strings.Contains(stderr, "1001") {
				t.Fatalf("262144 addresses x 1001 ports: stderr %q, want a refusal naming 262144 addresses and 1001 ports", stderr)
			}
			if calls := r.Calls(); len(calls) != 0 {
				t.Fatalf("nmap called: %+v", calls)
			}
		})
	}
}
