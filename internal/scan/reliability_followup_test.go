package scan_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

type rateOutageStore struct {
	*scantest.Store
	calls atomic.Int32
}

func (s *rateOutageStore) RecordRateSamples(context.Context, int64, []inventory.RateSample) error {
	s.calls.Add(1)
	return errors.New("dial tcp 127.0.0.1:5432: connection refused")
}

func TestRateSampleWriteOutageAfterGroupSavedLeavesRunPaused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := &rateOutageStore{Store: &scantest.Store{}}
		r := &nmaptest.Runner{DiscoverFunc: allUp, ServicesFunc: openPorts(80)}
		settings := inventory.RunSettings{Targets: []string{"10.23.0.1"}, Ports: []int{80}, MaxRate: 100, Workers: 1}
		s := &scan.Scanner{Store: st, Runner: r, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
		err := s.Run(context.Background(), testRun(settings))
		if len(st.Groups()) != 1 {
			t.Fatalf("groups recorded = %d, want the group saved before the rate-sample write", len(st.Groups()))
		}
		if got := st.Statuses(); len(got) == 0 || got[len(got)-1] == inventory.RunFailed {
			t.Fatalf("rate-sample write fails after the group is saved: statuses = %v, Run = %v; want the run paused (resumable) or completed, not failed", got, err)
		}
		if got := st.Statuses(); got[len(got)-1] == inventory.RunPaused && st.calls.Load() < 2 {
			t.Errorf("run paused after %d rate-sample attempts, want the write retried like the group write", st.calls.Load())
		}
	})
}

func TestPlanRefusesAddressesTimesPortsAboveCeiling(t *testing.T) {
	ports := make([]int, 1001)
	for i := range ports {
		ports[i] = i + 1
	}
	s := &scan.Scanner{Store: &scantest.Store{}, Runner: &nmaptest.Runner{}, Transport: (&scantest.Transport{}).For, Clock: scantest.NewClock(time.Unix(0, 0))}
	p, err := s.Plan(context.Background(), inventory.RunSettings{Targets: []string{"10.0.0.0/14"}, Ports: ports, MaxRate: 100, Workers: 1})
	if err == nil {
		t.Fatalf("plan preview of 262144 addresses x 1001 ports = %d addresses, %d groups, want a refusal above the work ceiling", p.Addresses, p.Groups)
	}
	if !strings.Contains(err.Error(), "26214") || !strings.Contains(err.Error(), "1001") {
		t.Fatalf("plan preview error %q, want it to name 262144 addresses and 1001 ports", err)
	}
}
