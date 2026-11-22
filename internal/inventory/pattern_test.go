package inventory

import (
	"testing"
	"time"
)

func observations(day time.Time, seenHours, missedHours, uncoveredHours []int) []PresenceObservation {
	var obs []PresenceObservation
	add := func(hours []int, covered, seen bool) {
		for i, h := range hours {
			at := day.AddDate(0, 0, i).Add(time.Duration(h)*time.Hour + 15*time.Minute)
			obs = append(obs, PresenceObservation{At: at, Covered: covered, Seen: seen})
		}
	}
	add(seenHours, true, true)
	add(missedHours, true, false)
	add(uncoveredHours, false, true)
	return obs
}

// REQ-INVENTORY-012
func TestTimeOfDay(t *testing.T) {
	day := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		obs   []PresenceObservation
		label string
		ok    bool
	}{
		{"office hours over 6 covering runs", observations(day, []int{8, 11, 15}, []int{2, 20, 23}, nil), "08:00-16:00", true},
		{"office hours over many runs", observations(day, []int{8, 9, 12, 14, 15, 10}, []int{0, 3, 17, 19, 22, 6}, nil), "08:00-16:00", true},
		{"night window wraps midnight", observations(day, []int{22, 23, 1, 2}, []int{9, 12, 15}, nil), "22:00-03:00", true},
		{"only 5 covering runs", observations(day, []int{8, 11, 15}, []int{2, 20}, nil), "", false},
		{"uncovered runs are not counted", observations(day, []int{8, 11, 15}, []int{2, 20}, []int{3, 4, 5}), "", false},
		{"uncovered runs do not break a pattern", observations(day, []int{8, 11, 15}, []int{2, 20, 23}, []int{1, 21}), "08:00-16:00", true},
		{"seen and missed at the same hour", observations(day, []int{8, 11, 15}, []int{11, 20, 23}, nil), "", false},
		{"missed inside the seen window", observations(day, []int{8, 11, 15}, []int{12, 20, 23}, nil), "", false},
		{"always seen", observations(day, []int{1, 5, 8, 11, 15, 20}, nil, nil), "", false},
		{"never seen", observations(day, nil, []int{1, 5, 8, 11, 15, 20}, nil), "", false},
		{"no observations", nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := TimeOfDay(tc.obs, nil)
			if ok != tc.ok || (ok && p.Label() != tc.label) {
				t.Errorf("TimeOfDay = %+v %q %v, want %q %v", p, p.Label(), ok, tc.label, tc.ok)
			}
		})
	}
}

// REQ-INVENTORY-012
func TestTimeOfDayUsesLocation(t *testing.T) {
	warsaw := time.FixedZone("CET", 3600)
	day := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	obs := observations(day, []int{7, 10, 14}, []int{1, 19, 22}, nil)
	if p, ok := TimeOfDay(obs, nil); !ok || p.Label() != "07:00-15:00" {
		t.Errorf("UTC: %q %v, want 07:00-15:00", p.Label(), ok)
	}
	if p, ok := TimeOfDay(obs, warsaw); !ok || p.Label() != "08:00-16:00" {
		t.Errorf("CET: %q %v, want 08:00-16:00", p.Label(), ok)
	}
}
