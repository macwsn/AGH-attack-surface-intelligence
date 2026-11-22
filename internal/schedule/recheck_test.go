package schedule

import (
	"slices"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
)

func recheckDefinition(f Frequency, every string) Definition {
	return Definition{
		Name:          "rhythm",
		InactiveAfter: 3,
		Settings:      inventory.RunSettings{Targets: []string{"10.0.0.0/28"}, Ports: []int{80}, MaxRate: 50, Workers: 1},
		Schedule:      Schedule{Timezone: "Europe/Warsaw", Frequency: f, RecheckEvery: every},
	}
}

func TestValidateRecheckEvery(t *testing.T) {
	interval := Frequency{Kind: FrequencyInterval, Every: "6h"}
	daily := Frequency{Kind: FrequencyDaily}
	weekly := Frequency{Kind: FrequencyWeekly}
	for _, c := range []struct {
		freq    Frequency
		every   string
		problem string
	}{
		{daily, "", ""},
		{daily, "1h", ""},
		{daily, "1m", ""},
		{daily, "23h59m", ""},
		{interval, "5h", ""},
		{weekly, "167h", ""},
		{daily, "30s", "at least 1m"},
		{daily, "soon", "at least 1m"},
		{daily, "24h", "shorter than the full scan frequency (24h0m0s)"},
		{daily, "48h", "shorter than the full scan frequency"},
		{interval, "6h", "shorter than the full scan frequency (6h0m0s)"},
		{weekly, "168h", "shorter than the full scan frequency (168h0m0s)"},
	} {
		err := recheckDefinition(c.freq, c.every).Validate()
		if c.problem == "" {
			if err != nil {
				t.Errorf("%s recheck %q: unexpected error %v", c.freq, c.every, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s recheck %q: no error, want %q", c.freq, c.every, c.problem)
			continue
		}
		lines := strings.Split(err.Error(), "\n")
		if len(lines) != 1 || !strings.HasPrefix(lines[0], "recheck: ") || !strings.Contains(lines[0], c.problem) {
			t.Errorf("%s recheck %q: err = %q, want one line \"recheck: ...%s...\"", c.freq, c.every, err, c.problem)
		}
	}
}

func TestRecheckInterval(t *testing.T) {
	if _, ok := (Schedule{}).RecheckInterval(); ok {
		t.Error("empty recheck_every reports rechecks")
	}
	if d, ok := (Schedule{RecheckEvery: "90m"}).RecheckInterval(); !ok || d != 90*time.Minute {
		t.Errorf("RecheckInterval(90m) = %v, %v", d, ok)
	}
}

func periodicAt(up, down int) inventory.Availability {
	return inventory.BuildAvailability([]inventory.HourObservation{
		{Hour: up, Seen: true}, {Hour: up, Seen: true}, {Hour: up, Seen: true},
		{Hour: down, Seen: false}, {Hour: down, Seen: false}, {Hour: down, Seen: false},
	})
}

func TestPickRecheck(t *testing.T) {
	now := time.Date(2026, 11, 20, 2, 30, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	downNow := periodicAt(10, 2)
	upNow := periodicAt(2, 10)
	if downNow.Expected(2) != inventory.ExpectedDown || upNow.Expected(2) != inventory.ExpectedUp {
		t.Fatalf("fixture profiles: expected(2) = %q / %q", downNow.Expected(2), upNow.Expected(2))
	}
	plain := inventory.NewAvailability()
	hosts := []RecheckHost{
		{Address: "10.0.0.20", Availability: plain, LastSeen: ago(2 * time.Hour), LastCovered: ago(2 * time.Hour)},
		{Address: "10.0.0.9", Availability: plain, LastSeen: ago(2 * time.Hour), LastCovered: ago(2 * time.Hour)},
		{Address: "10.0.0.30", Availability: upNow, LastSeen: ago(2 * time.Hour), LastCovered: ago(2 * time.Hour)},
		{Address: "10.0.0.3", Availability: upNow, LastSeen: ago(2 * time.Hour), LastCovered: ago(time.Hour)},
		{Address: "10.0.0.5", Availability: downNow, LastSeen: ago(2 * time.Hour), LastCovered: ago(2 * time.Hour)},
		{Address: "10.0.0.6", Availability: downNow, LastSeen: ago(25 * time.Hour), LastCovered: ago(2 * time.Hour)},
		{Address: "10.0.0.7", Availability: plain, LastSeen: ago(10 * time.Minute), LastCovered: ago(10 * time.Minute)},
		{Address: "10.0.0.8", Availability: plain, LastSeen: ago(time.Hour)},
	}
	got := PickRecheck(now, time.Hour, hosts)
	want := []string{"10.0.0.3", "10.0.0.30", "10.0.0.6", "10.0.0.8", "10.0.0.9", "10.0.0.20"}
	if !slices.Equal(got, want) {
		t.Errorf("PickRecheck = %v, want %v", got, want)
	}
}

func TestPickRecheckCases(t *testing.T) {
	now := time.Date(2026, 11, 20, 2, 0, 0, 0, time.UTC)
	down := periodicAt(10, 2)
	for _, c := range []struct {
		name string
		host RecheckHost
		want bool
	}{
		{"expected down, seen 2h ago", RecheckHost{Address: "10.0.0.5", Availability: down, LastSeen: now.Add(-2 * time.Hour)}, false},
		{"expected down, seen 25h ago", RecheckHost{Address: "10.0.0.5", Availability: down, LastSeen: now.Add(-25 * time.Hour)}, true},
		{"expected down, seen exactly 24h ago", RecheckHost{Address: "10.0.0.5", Availability: down, LastSeen: now.Add(-24 * time.Hour)}, true},
		{"covered 10m ago, period 1h", RecheckHost{Address: "10.0.0.5", Availability: inventory.NewAvailability(),
			LastSeen: now.Add(-10 * time.Minute), LastCovered: now.Add(-10 * time.Minute)}, false},
		{"covered exactly 1h ago", RecheckHost{Address: "10.0.0.5", Availability: inventory.NewAvailability(),
			LastSeen: now.Add(-time.Hour), LastCovered: now.Add(-time.Hour)}, true},
		{"not periodic with 5 samples, low bucket now", RecheckHost{Address: "10.0.0.5", Availability: inventory.BuildAvailability([]inventory.HourObservation{
			{Hour: 10, Seen: true}, {Hour: 10, Seen: true}, {Hour: 10, Seen: true}, {Hour: 2, Seen: false}, {Hour: 2, Seen: false}}),
			LastSeen: now.Add(-2 * time.Hour)}, true},
	} {
		got := PickRecheck(now, time.Hour, []RecheckHost{c.host})
		if (len(got) == 1) != c.want {
			t.Errorf("%s: PickRecheck = %v, want picked %v", c.name, got, c.want)
		}
	}
	if got := PickRecheck(now, time.Hour, nil); len(got) != 0 {
		t.Errorf("PickRecheck(nil) = %v", got)
	}
}

func TestRecheckHostsKeepsHostsWithKnownServices(t *testing.T) {
	seen := time.Date(2026, 11, 20, 1, 0, 0, 0, time.UTC)
	hosts := []inventory.ExportHost{
		{Address: "10.0.0.1", LastSeen: seen, LastCovered: seen, Services: []inventory.ExportService{{Port: 80, Protocol: "tcp", Status: inventory.StatusActive}}},
		{Address: "10.0.0.2", Services: []inventory.ExportService{{Port: 80, Protocol: "tcp", Status: inventory.StatusUnstable}}},
		{Address: "10.0.0.3", Services: []inventory.ExportService{{Port: 80, Protocol: "tcp", Status: inventory.StatusInactive}}},
		{Address: "10.0.0.4", Services: []inventory.ExportService{{Port: 22, Protocol: "tcp", Status: inventory.StatusActive}}},
		{Address: "10.0.0.5"},
	}
	got := recheckHosts(hosts, []int{80, 443})
	if len(got) != 2 || got[0].Address != "10.0.0.1" || got[1].Address != "10.0.0.2" {
		t.Fatalf("recheckHosts = %+v, want 10.0.0.1 and 10.0.0.2", got)
	}
	if !got[0].LastSeen.Equal(seen) || !got[0].LastCovered.Equal(seen) || got[0].Availability.Samples != 0 {
		t.Errorf("recheckHosts[0] = %+v", got[0])
	}
}
