package schedule

import (
	"testing"
	"time"

	"asi/internal/inventory"
)

// REQ-SCHEDULE-006
func TestProgressOf(t *testing.T) {
	groups := []inventory.GroupInfo{
		{AddressCount: 64, HostsFound: 3, Duration: 40 * time.Second},
		{AddressCount: 64, HostsFound: 1, Duration: 24 * time.Second},
	}
	p := ProgressOf(512, 2, groups)
	if p.Done != 128 || p.Groups != 2 || p.Hosts != 4 || p.Percent != 25 || p.Busy != 64*time.Second {
		t.Fatalf("progress = %+v", p)
	}
	if !p.HasLeft || p.Left != 96*time.Second {
		t.Errorf("left = %s %v, want 96s (384 addresses at 0.5 s per address on 2 workers)", p.Left, p.HasLeft)
	}
	if p := ProgressOf(512, 2, nil); p.HasLeft || p.Percent != 0 {
		t.Errorf("no groups: %+v, want no estimate", p)
	}
	if p := ProgressOf(128, 2, groups); p.HasLeft || p.Percent != 100 {
		t.Errorf("all done: %+v, want 100%% and no estimate", p)
	}
}
