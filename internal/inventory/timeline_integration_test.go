//go:build integration

package inventory

import (
	"context"
	"errors"
	"testing"
	"time"

	"asi/internal/probe"
)

func titled(addr, title string) HostResult {
	return HostResult{Address: addr, Services: []ServiceResult{{Port: 80, Protocol: "tcp", State: "open", Service: "http",
		HTTP: &probe.HTTP{StatusCode: 200, Title: title}}}}
}

// REQ-INVENTORY-014
func TestHostTimeline(t *testing.T) {
	inv, _ := openInventory(t)
	ctx := context.Background()
	const a, b = "10.0.0.7", "10.0.0.8"
	r1 := mustRun(t, inv, "t1", 3)
	mustRecord(t, inv, r1, GroupResult{Addresses: []string{a, b}, Hosts: []HostResult{titled(a, "v1"), titled(b, "x")}})
	r2 := mustRun(t, inv, "t2", 3)
	mustRecord(t, inv, r2, GroupResult{Addresses: []string{a, b}, Hosts: []HostResult{titled(b, "x")}})
	r3 := mustRun(t, inv, "t3", 3)
	mustRecord(t, inv, r3, GroupResult{Addresses: []string{b}, Hosts: []HostResult{titled(b, "x")}})
	r4 := mustRun(t, inv, "t4", 3)
	mustRecord(t, inv, r4, GroupResult{Addresses: []string{a, b}, Hosts: []HostResult{titled(a, "v2"), titled(b, "x")}})

	tl, err := inv.HostTimeline(ctx, a)
	if err != nil {
		t.Fatalf("HostTimeline: %v", err)
	}
	type cell struct {
		run           string
		covered, seen bool
		title         string
	}
	var got []cell
	for _, e := range tl.Entries {
		c := cell{run: e.Run.Name, covered: e.Covered, seen: e.Seen}
		if e.State != nil && len(e.State.Services) == 1 {
			c.title = e.State.Services[0].HTTP.Title
		}
		got = append(got, c)
	}
	want := []cell{{"t1", true, true, "v1"}, {"t2", true, false, "v1"}, {"t3", false, false, ""}, {"t4", true, true, "v2"}}
	if len(got) != len(want) {
		t.Fatalf("entries = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	score, reasons := Score(tl.Host, r4.StartedAt, nil)
	if tl.Host.Address != a || tl.Score != score || len(tl.Reasons) != len(reasons) || tl.Host.InterestScore != score {
		t.Errorf("host %+v score %d reasons %+v, want %d %+v", tl.Host, tl.Score, tl.Reasons, score, reasons)
	}
	if tl.Usual {
		t.Errorf("pattern %v with 3 covering runs", tl.Pattern)
	}
	if !tl.Entries[2].At.Equal(r3.StartedAt) {
		t.Errorf("uncovered run time = %v, want run start %v", tl.Entries[2].At, r3.StartedAt)
	}

	if _, err := inv.HostTimeline(ctx, "10.0.0.99"); !errors.Is(err, ErrUnknownHost) {
		t.Errorf("unknown host error = %v, want ErrUnknownHost", err)
	}

}

// REQ-INVENTORY-014
func TestHostTimelineUsualHours(t *testing.T) {
	inv, st := openInventory(t)
	ctx := context.Background()
	const a = "10.0.1.7"
	day := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	hours := []struct {
		hour int
		seen bool
	}{{9, true}, {22, false}, {11, true}, {3, false}, {15, true}, {19, false}, {8, true}}
	for i, h := range hours {
		r := mustRun(t, inv, "day-"+string(rune('a'+i)), 3)
		g := GroupResult{Addresses: []string{a}}
		if h.seen {
			g.Hosts = []HostResult{titled(a, "Office")}
		}
		mustRecord(t, inv, r, g)
		at := day.AddDate(0, 0, i).Add(time.Duration(h.hour)*time.Hour + 20*time.Minute)
		if _, err := st.Pool.Exec(ctx, `UPDATE run_groups SET completed_at = $2 WHERE run_id = $1`, r.ID, at); err != nil {
			t.Fatal(err)
		}
	}
	tl, err := inv.HostTimeline(ctx, a)
	if err != nil {
		t.Fatalf("HostTimeline: %v", err)
	}
	if !tl.Usual || tl.Pattern.Label() != "08:00-16:00" {
		t.Fatalf("pattern = %q usual %v, want 08:00-16:00", tl.Pattern.Label(), tl.Usual)
	}
}
