package schedule

import (
	"testing"
	"time"
)

// REQ-SCHEDULE-008: AC5 of T-803xb7cwjk
func TestNextPlanned(t *testing.T) {
	warsaw, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, warsaw)
	ranToday := now.Add(-time.Hour)
	windows, err := ParseWindows("mon-fri 22:00-06:00")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		s    Schedule
		last *time.Time
		want time.Time
	}{
		{"never ran, no windows: now", Schedule{Timezone: "Europe/Warsaw", Frequency: Frequency{Kind: FrequencyDaily}}, nil, now},
		{"daily, ran today: next midnight", Schedule{Timezone: "Europe/Warsaw", Frequency: Frequency{Kind: FrequencyDaily}}, &ranToday, time.Date(2026, 11, 19, 0, 0, 0, 0, warsaw)},
		{"interval 6h", Schedule{Timezone: "Europe/Warsaw", Frequency: Frequency{Kind: FrequencyInterval, Every: "6h"}}, &ranToday, ranToday.Add(6 * time.Hour)},
		{"daily in a night window, ran today: tonight's window counts as today, so tomorrow 22:00", Schedule{Timezone: "Europe/Warsaw", Windows: windows, Frequency: Frequency{Kind: FrequencyDaily}}, &ranToday, time.Date(2026, 11, 19, 22, 0, 0, 0, warsaw)},
		{"never ran, night window: tonight 22:00", Schedule{Timezone: "Europe/Warsaw", Windows: windows, Frequency: Frequency{Kind: FrequencyDaily}}, nil, time.Date(2026, 11, 18, 22, 0, 0, 0, warsaw)},
	} {
		got, ok := tc.s.NextPlanned(tc.last, now)
		if !ok || !got.Equal(tc.want) {
			t.Errorf("%s: NextPlanned = %s %v, want %s", tc.name, got, ok, tc.want)
		}
	}
}
