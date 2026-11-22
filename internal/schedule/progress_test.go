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

// REQ-SCHEDULE-006: AC2 of T-803xb7cwjk
func TestProgressWithInFlight(t *testing.T) {
	if p := ProgressOf(64, 1, nil).WithInFlight(16); p.Done != 16 || p.Percent != 25 || p.HasLeft {
		t.Errorf("16 of 64 in flight before any group: %+v, want 25%% and no time left yet", p)
	}
	groups := []inventory.GroupInfo{{AddressCount: 60, Duration: time.Minute}}
	if p := ProgressOf(64, 1, groups).WithInFlight(16); p.Done != 64 || p.Percent != 100 {
		t.Errorf("in flight beyond the total: %+v, want capped at 64", p)
	}
	if p := ProgressOf(64, 1, nil).WithInFlight(-3); p.Done != 0 || p.Percent != 0 {
		t.Errorf("negative in flight: %+v, want unchanged", p)
	}
}
