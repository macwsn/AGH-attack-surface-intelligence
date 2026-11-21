package schedule

import (
	"strings"
	"testing"
	"time"
)

func utc(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func mustWindows(t *testing.T, text string) []Window {
	t.Helper()
	ws, err := ParseWindows(text)
	if err != nil {
		t.Fatalf("ParseWindows(%q): %v", text, err)
	}
	return ws
}

// REQ-SCHEDULE-002
func TestWindowAt(t *testing.T) {
	cases := []struct {
		name      string
		tz        string
		windows   string
		at        string
		in        bool
		start     string
		end       string
		nextStart string
	}{
		{name: "inside a day window", tz: "Europe/Warsaw", windows: "mon-fri 08:00-16:00", at: "2026-11-18T09:00:00Z",
			in: true, start: "2026-11-18T07:00:00Z", end: "2026-11-18T15:00:00Z"},
		{name: "end is exclusive", tz: "Europe/Warsaw", windows: "mon-fri 08:00-16:00", at: "2026-11-18T15:00:00Z",
			nextStart: "2026-11-19T07:00:00Z"},
		{name: "weekend is outside", tz: "Europe/Warsaw", windows: "mon-fri 08:00-16:00", at: "2026-11-21T09:00:00Z",
			nextStart: "2026-11-23T07:00:00Z"},
		{name: "crossing midnight, after midnight", tz: "Europe/Warsaw", windows: "mon-fri 22:00-06:00", at: "2026-11-21T02:00:00Z",
			in: true, start: "2026-11-20T21:00:00Z", end: "2026-11-21T05:00:00Z"},
		{name: "crossing midnight, before midnight", tz: "Europe/Warsaw", windows: "mon-fri 22:00-06:00", at: "2026-11-20T22:30:00Z",
			in: true, start: "2026-11-20T21:00:00Z", end: "2026-11-21T05:00:00Z"},
		{name: "crossing midnight belongs to the start day", tz: "Europe/Warsaw", windows: "mon-fri 22:00-06:00", at: "2026-11-16T02:00:00Z",
			nextStart: "2026-11-16T21:00:00Z"},
		{name: "whole days join", tz: "Europe/Warsaw", windows: "sat,sun 00:00-00:00", at: "2026-11-21T11:00:00Z",
			in: true, start: "2026-11-20T23:00:00Z", end: "2026-11-22T23:00:00Z"},
		{name: "touching windows join across midnight", tz: "UTC", windows: "mon 20:00-00:00\ntue 00:00-04:00", at: "2026-11-16T21:00:00Z",
			in: true, start: "2026-11-16T20:00:00Z", end: "2026-11-17T04:00:00Z"},
		{name: "spring forward shortens the window to 2h", tz: "Europe/Warsaw", windows: "sun 01:00-04:00", at: "2026-03-29T01:30:00Z",
			in: true, start: "2026-03-29T00:00:00Z", end: "2026-03-29T02:00:00Z"},
		{name: "start in the spring gap moves one hour later", tz: "Europe/Warsaw", windows: "sun 02:30-05:00", at: "2026-03-29T01:00:00Z",
			nextStart: "2026-03-29T01:30:00Z"},
		{name: "start in the spring gap, inside", tz: "Europe/Warsaw", windows: "sun 02:30-05:00", at: "2026-03-29T01:30:00Z",
			in: true, start: "2026-03-29T01:30:00Z", end: "2026-03-29T03:00:00Z"},
		{name: "fall back lengthens a night window to 9h", tz: "Europe/Warsaw", windows: "sat 22:00-06:00", at: "2026-10-25T04:30:00Z",
			in: true, start: "2026-10-24T20:00:00Z", end: "2026-10-25T05:00:00Z"},
		{name: "fall back, first 02:30 is inside", tz: "Europe/Warsaw", windows: "sat 22:00-06:00", at: "2026-10-25T00:30:00Z",
			in: true, start: "2026-10-24T20:00:00Z", end: "2026-10-25T05:00:00Z"},
		{name: "fall back, after the window", tz: "Europe/Warsaw", windows: "sat 22:00-06:00", at: "2026-10-25T05:00:00Z",
			nextStart: "2026-10-31T21:00:00Z"},
		{name: "other timezone", tz: "America/New_York", windows: "mon 09:00-10:00", at: "2026-11-16T14:30:00Z",
			in: true, start: "2026-11-16T14:00:00Z", end: "2026-11-16T15:00:00Z"},
		{name: "us spring forward on another date", tz: "America/New_York", windows: "sun 01:00-04:00", at: "2026-03-08T07:30:00Z",
			in: true, start: "2026-03-08T06:00:00Z", end: "2026-03-08T08:00:00Z"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := Schedule{Timezone: c.tz, Windows: mustWindows(t, c.windows), Frequency: Frequency{Kind: FrequencyDaily}}
			if err := s.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			at := utc(c.at)
			sp, in := s.WindowAt(at)
			if in != c.in {
				t.Fatalf("WindowAt(%s) in = %v, want %v (span %v)", c.at, in, c.in, sp)
			}
			if c.in && (!sp.Start.Equal(utc(c.start)) || !sp.End.Equal(utc(c.end))) {
				t.Errorf("span = %s - %s, want %s - %s", sp.Start.UTC().Format(time.RFC3339), sp.End.UTC().Format(time.RFC3339), c.start, c.end)
			}
			if c.nextStart != "" {
				next, ok := s.NextStart(at)
				if !ok || !next.Equal(utc(c.nextStart)) {
					t.Errorf("NextStart = %s %v, want %s", next.UTC().Format(time.RFC3339), ok, c.nextStart)
				}
			}
		})
	}
}

func TestNoWindowsAllowsAnyTime(t *testing.T) {
	s := Schedule{Frequency: Frequency{Kind: FrequencyDaily}}
	sp, in := s.WindowAt(utc("2026-11-18T09:00:00Z"))
	if !in || !sp.End.IsZero() {
		t.Fatalf("WindowAt = %v %v, want inside with no end", sp, in)
	}
}

// REQ-SCHEDULE-003
func TestDue(t *testing.T) {
	night := Schedule{Timezone: "Europe/Warsaw", Windows: []Window{{Days: []time.Weekday{1, 2, 3, 4, 5}, Start: "22:00", End: "06:00"}}}
	cases := []struct {
		name  string
		s     Schedule
		freq  Frequency
		last  string
		now   string
		due   bool
		noWin bool
	}{
		{name: "never ran", s: night, freq: Frequency{Kind: FrequencyWeekly}, now: "2026-11-16T21:00:00Z", due: true},
		{name: "interval elapsed", freq: Frequency{Kind: FrequencyInterval, Every: "6h"}, last: "2026-11-16T03:00:00Z", now: "2026-11-16T09:00:00Z", due: true, noWin: true},
		{name: "interval not elapsed", freq: Frequency{Kind: FrequencyInterval, Every: "6h"}, last: "2026-11-16T03:00:00Z", now: "2026-11-16T08:59:59Z", noWin: true},
		{name: "daily, same window after midnight", s: night, freq: Frequency{Kind: FrequencyDaily}, last: "2026-11-16T21:00:00Z", now: "2026-11-17T00:30:00Z"},
		{name: "daily, next window", s: night, freq: Frequency{Kind: FrequencyDaily}, last: "2026-11-16T21:00:00Z", now: "2026-11-17T21:00:00Z", due: true},
		{name: "daily, local midnight during DST change", freq: Frequency{Kind: FrequencyDaily}, last: "2026-03-28T22:30:00Z", now: "2026-03-28T23:30:00Z", due: true, noWin: true},
		{name: "daily, same local day although UTC dates differ", freq: Frequency{Kind: FrequencyDaily}, last: "2026-03-28T23:10:00Z", now: "2026-03-29T20:00:00Z", noWin: true},
		{name: "weekly, same ISO week", s: night, freq: Frequency{Kind: FrequencyWeekly}, last: "2026-11-16T21:00:00Z", now: "2026-11-20T21:00:00Z"},
		{name: "weekly, next ISO week", s: night, freq: Frequency{Kind: FrequencyWeekly}, last: "2026-11-20T21:00:00Z", now: "2026-11-23T21:00:00Z", due: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := c.s
			if s.Timezone == "" {
				s.Timezone = "Europe/Warsaw"
			}
			if c.noWin {
				s.Windows = nil
			}
			s.Frequency = c.freq
			if err := s.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			now := utc(c.now)
			w, in := s.WindowAt(now)
			if !in {
				t.Fatalf("%s is outside the windows", c.now)
			}
			var last *time.Time
			if c.last != "" {
				l := utc(c.last)
				last = &l
			}
			if got := s.Due(last, now, w); got != c.due {
				t.Errorf("Due(%s, %s) = %v, want %v", c.last, c.now, got, c.due)
			}
		})
	}
}

// REQ-SCHEDULE-001
func TestParseWindows(t *testing.T) {
	ws, err := ParseWindows("mon-fri 22:00-06:00\n\n Sat,SUN 00:00-00:00 \nfri-mon 01:00-02:00")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := FormatWindows(ws), "mon-fri 22:00-06:00\nsat-sun 00:00-00:00\nmon,fri-sun 01:00-02:00"; got != want {
		t.Errorf("FormatWindows = %q, want %q", got, want)
	}
	for _, bad := range []string{"mon 25:00-06:00", "funday 01:00-02:00", "mon 01:00", "mon 1:00-2:00", "01:00-02:00"} {
		if _, err := ParseWindows(bad); err == nil || !strings.Contains(err.Error(), "line 1") {
			t.Errorf("ParseWindows(%q) err = %v, want a line 1 error", bad, err)
		}
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]Schedule{
		"unknown timezone": {Timezone: "Mars/Olympus", Frequency: Frequency{Kind: FrequencyDaily}},
		"short interval":   {Frequency: Frequency{Kind: FrequencyInterval, Every: "30s"}},
		"bad interval":     {Frequency: Frequency{Kind: FrequencyInterval, Every: "often"}},
		"no frequency":     {},
		"no weekdays":      {Windows: []Window{{Start: "01:00", End: "02:00"}}, Frequency: Frequency{Kind: FrequencyDaily}},
	}
	for name, s := range cases {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded", name)
		}
	}
}
