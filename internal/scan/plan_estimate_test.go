package scan_test

import (
	"context"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

func planOf(t *testing.T, st inventory.RunSettings) scan.Plan {
	t.Helper()
	s := &scan.Scanner{Store: &scantest.Store{}, Runner: &nmaptest.Runner{}, Transport: (&scantest.Transport{}).For}
	p, err := s.Plan(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// REQ-SCAN-021: AC3 of T-803xb7cwjk
func TestPlanEstimate(t *testing.T) {
	big := planOf(t, inventory.RunSettings{Targets: []string{"10.0.0.0/18"}, Ports: []int{22, 80, 443, 3389, 8080, 8443}, MaxRate: 1000, Workers: 4})
	if big.EstimateLow <= 0 || big.EstimateHigh < big.EstimateLow || big.EstimateHigh >= time.Hour {
		t.Errorf("/18 with 6 ports at rate 1000: estimate %s-%s, want minutes below an hour", big.EstimateLow, big.EstimateHigh)
	}
	if big.AtMaxRate < time.Hour {
		t.Errorf("worst case = %s, want the every-address-live bound to stay above an hour (the estimate must differ from it)", big.AtMaxRate)
	}
	lab := planOf(t, inventory.RunSettings{Targets: []string{"172.30.0.0/24"}, Excludes: []string{"172.30.0.1", "172.30.0.2", "172.30.0.3"},
		Ports: []int{22, 80, 443, 6379, 8000, 8080, 8081}, MaxRate: 300, Workers: 4})
	if lab.EstimateHigh >= 2*time.Minute {
		t.Errorf("lab /24: estimate up to %s, want under 2 minutes", lab.EstimateHigh)
	}

	shared := big
	shared.UseLiveShare(0.5)
	if shared.EstimateHigh <= big.EstimateHigh || shared.LiveShare != 0.5 {
		t.Errorf("history live share 50%%: estimate %s-%s, want longer than with %v%% (%s)", shared.EstimateLow, shared.EstimateHigh, scan.DefaultLiveShare*100, big.EstimateHigh)
	}

	measured := big
	measured.Measured(float64(big.Addresses) / 120)
	if measured.EstimateLow != 96*time.Second || measured.EstimateHigh != 150*time.Second {
		t.Errorf("measured %d addresses in 2 min: estimate %s-%s, want 1m36s-2m30s", big.Addresses, measured.EstimateLow, measured.EstimateHigh)
	}
	measured.UseLiveShare(0.5)
	if measured.EstimateLow != 96*time.Second {
		t.Errorf("measured speed must drive the estimate over the live-share model: %s", measured.EstimateLow)
	}
}
