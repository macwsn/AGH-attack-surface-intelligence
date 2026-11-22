package scan_test

import (
	"strconv"
	"testing"

	"asi/internal/inventory"
)

func recheckNmapCalls(t *testing.T, lab map[string][]int) map[string]int {
	t.Helper()
	settings := inventory.RunSettings{
		Targets:  []string{"172.30.0.0/24"},
		Excludes: []string{"172.30.0.1", "172.30.0.2", "172.30.0.3"},
		Ports:    []int{22, 80, 443, 6379, 8000, 8080, 8081},
		MaxRate:  300, Workers: 4, Mode: inventory.ModeRecheck,
	}
	res := runMode(t, &fakeLAN{open: lab}, knownOf(lab), nil, settings)
	if res.err != nil {
		t.Fatal(res.err)
	}
	if got := len(res.store.Groups()); got != 1 {
		t.Fatalf("recheck of %d hosts recorded %d groups, want one", len(lab), got)
	}
	calls := map[string]int{}
	for _, c := range res.runner.Calls() {
		calls[c.Method]++
		calls["total"]++
	}
	return calls
}

// AC3: a recheck of 11 known hosts in one group calls nmap a constant number of times, not once per host
// (or per distinct set of known ports, which on the lab is almost one per host).
func TestReproRecheckNmapInvocationsAreConstantNotPerHost(t *testing.T) {
	two := map[string][]int{"172.30.0.10": {80, 8080}, "172.30.0.11": {22, 6379}}
	eleven := map[string][]int{}
	for i := 0; i < 11; i++ {
		ports := []int{80}
		switch i % 4 {
		case 1:
			ports = []int{22}
		case 2:
			ports = []int{80, 8080}
		case 3:
			ports = []int{6379}
		}
		eleven["172.30.0."+strconv.Itoa(10+i)] = ports
	}
	small, large := recheckNmapCalls(t, two), recheckNmapCalls(t, eleven)
	t.Logf("nmap calls: 2 hosts %v, 11 hosts %v", small, large)
	if large["total"] != small["total"] {
		t.Errorf("recheck of 11 hosts in one group made %d nmap calls, 2 hosts with the same known ports made %d; want a constant count, not per host (%v vs %v)",
			large["total"], small["total"], large, small)
	}
	if large["total"] >= 11 {
		t.Errorf("recheck of 11 hosts in one group made %d nmap calls, want fewer than one per host (%v)", large["total"], large)
	}
}
