package schedule

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	FrequencyInterval = "interval"
	FrequencyDaily    = "daily"
	FrequencyWeekly   = "weekly"
	MinInterval       = time.Minute
)

type Schedule struct {
	Timezone     string    `json:"timezone"`
	Windows      []Window  `json:"windows"`
	Frequency    Frequency `json:"frequency"`
	RecheckEvery string    `json:"recheck_every,omitempty"`
}

type Window struct {
	Days  []time.Weekday `json:"days"`
	Start string         `json:"start"`
	End   string         `json:"end"`
}

type Frequency struct {
	Kind  string `json:"kind"`
	Every string `json:"every,omitempty"`
}

type Span struct {
	Start time.Time
	End   time.Time
}

var dayNames = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

func (s Schedule) Location() (*time.Location, error) {
	if s.Timezone == "" {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		return nil, fmt.Errorf("unknown timezone %q", s.Timezone)
	}
	return loc, nil
}

func (s Schedule) Validate() error {
	if _, err := s.Location(); err != nil {
		return err
	}
	for i, w := range s.Windows {
		if err := w.validate(); err != nil {
			return fmt.Errorf("window %d: %w", i+1, err)
		}
	}
	if err := s.Frequency.validate(); err != nil {
		return err
	}
	return s.validateRecheck()
}

func (s Schedule) RecheckInterval() (time.Duration, bool) {
	if s.RecheckEvery == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s.RecheckEvery)
	return d, err == nil && d >= MinInterval
}

func (f Frequency) period() (time.Duration, bool) {
	switch f.Kind {
	case FrequencyDaily:
		return 24 * time.Hour, true
	case FrequencyWeekly:
		return 7 * 24 * time.Hour, true
	case FrequencyInterval:
		d, err := time.ParseDuration(f.Every)
		return d, err == nil
	}
	return 0, false
}

func (s Schedule) validateRecheck() error {
	if s.RecheckEvery == "" {
		return nil
	}
	d, err := time.ParseDuration(s.RecheckEvery)
	if err != nil || d < MinInterval {
		return fmt.Errorf("%q must be a duration of at least %s, for example 1h or 30m", s.RecheckEvery, MinInterval)
	}
	if full, ok := s.Frequency.period(); ok && d >= full {
		return fmt.Errorf("%q must be shorter than the full scan frequency (%s)", s.RecheckEvery, full)
	}
	return nil
}

func (w Window) validate() error {
	if len(w.Days) == 0 {
		return errors.New("no weekdays")
	}
	for _, d := range w.Days {
		if d < time.Sunday || d > time.Saturday {
			return fmt.Errorf("invalid weekday %d", d)
		}
	}
	if _, err := clockMinutes(w.Start); err != nil {
		return err
	}
	_, err := clockMinutes(w.End)
	return err
}

func (f Frequency) validate() error {
	switch f.Kind {
	case FrequencyDaily, FrequencyWeekly:
		return nil
	case FrequencyInterval:
		d, err := time.ParseDuration(f.Every)
		if err != nil || d < MinInterval {
			return fmt.Errorf("interval %q must be a duration of at least %s, for example 6h or 90m", f.Every, MinInterval)
		}
		return nil
	}
	return fmt.Errorf("frequency must be %s, %s or %s, got %q", FrequencyInterval, FrequencyDaily, FrequencyWeekly, f.Kind)
}

func clockMinutes(s string) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || len(h) != 2 || len(m) != 2 || err1 != nil || err2 != nil || hh > 23 || mm > 59 || hh < 0 || mm < 0 {
		return 0, fmt.Errorf("%q is not a time of day (HH:MM)", s)
	}
	return hh*60 + mm, nil
}

func (w Window) span(y int, mo time.Month, d int, loc *time.Location) Span {
	start, _ := clockMinutes(w.Start)
	end, _ := clockMinutes(w.End)
	ed := d
	if end <= start {
		ed++
	}
	return Span{
		Start: time.Date(y, mo, d, start/60, start%60, 0, 0, loc),
		End:   time.Date(y, mo, ed, end/60, end%60, 0, 0, loc),
	}
}

func (s Schedule) spans(t time.Time, loc *time.Location) []Span {
	lt := t.In(loc)
	var out []Span
	for off := -1; off <= 8; off++ {
		day := time.Date(lt.Year(), lt.Month(), lt.Day()+off, 12, 0, 0, 0, loc)
		for _, w := range s.Windows {
			if slices.Contains(w.Days, day.Weekday()) {
				if sp := w.span(day.Year(), day.Month(), day.Day(), loc); sp.End.After(sp.Start) {
					out = append(out, sp)
				}
			}
		}
	}
	return out
}

func (s Schedule) WindowAt(t time.Time) (Span, bool) {
	if len(s.Windows) == 0 {
		return Span{Start: t}, true
	}
	loc, err := s.Location()
	if err != nil {
		return Span{}, false
	}
	spans := s.spans(t, loc)
	cur, found := Span{}, false
	for _, sp := range spans {
		if !t.Before(sp.Start) && t.Before(sp.End) {
			if !found {
				cur, found = sp, true
			}
			if sp.Start.Before(cur.Start) {
				cur.Start = sp.Start
			}
			if sp.End.After(cur.End) {
				cur.End = sp.End
			}
		}
	}
	if !found {
		return Span{}, false
	}
	for grown := true; grown; {
		grown = false
		for _, sp := range spans {
			if !sp.Start.After(cur.End) && sp.End.After(cur.End) {
				cur.End, grown = sp.End, true
			}
			if !sp.End.Before(cur.Start) && sp.Start.Before(cur.Start) {
				cur.Start, grown = sp.Start, true
			}
		}
	}
	return cur, true
}

func (s Schedule) NextStart(t time.Time) (time.Time, bool) {
	loc, err := s.Location()
	if err != nil || len(s.Windows) == 0 {
		return time.Time{}, false
	}
	var next time.Time
	for _, sp := range s.spans(t, loc) {
		if sp.Start.After(t) && (next.IsZero() || sp.Start.Before(next)) {
			next = sp.Start
		}
	}
	return next, !next.IsZero()
}

func (s Schedule) NextPlanned(last *time.Time, now time.Time) (time.Time, bool) {
	loc, err := s.Location()
	if err != nil {
		return time.Time{}, false
	}
	candidates := []time.Time{now}
	if last != nil {
		switch s.Frequency.Kind {
		case FrequencyInterval:
			if d, err := time.ParseDuration(s.Frequency.Every); err == nil {
				candidates = append(candidates, last.Add(d))
			}
		case FrequencyDaily:
			y, m, d := now.In(loc).Date()
			candidates = append(candidates, time.Date(y, m, d+1, 0, 0, 0, 0, loc))
		case FrequencyWeekly:
			y, m, d := now.In(loc).Date()
			wd := (int(now.In(loc).Weekday()) + 6) % 7
			candidates = append(candidates, time.Date(y, m, d+7-wd, 0, 0, 0, 0, loc))
		}
	}
	for t, i := now, 0; i < 32; i++ {
		next, ok := s.NextStart(t)
		if !ok {
			break
		}
		candidates = append(candidates, next)
		t = next
	}
	slices.SortFunc(candidates, func(a, b time.Time) int { return a.Compare(b) })
	for _, c := range candidates {
		if c.Before(now) {
			continue
		}
		if w, ok := s.WindowAt(c); ok && s.Due(last, c, w) {
			return c, true
		}
	}
	return time.Time{}, false
}

func (s Schedule) Due(last *time.Time, now time.Time, window Span) bool {
	if last == nil {
		return true
	}
	loc, err := s.Location()
	if err != nil {
		return false
	}
	ref := window.Start
	if ref.IsZero() {
		ref = now
	}
	switch s.Frequency.Kind {
	case FrequencyInterval:
		d, err := time.ParseDuration(s.Frequency.Every)
		return err == nil && !now.Before(last.Add(d))
	case FrequencyDaily:
		ly, lm, ld := last.In(loc).Date()
		ry, rm, rd := ref.In(loc).Date()
		return time.Date(ly, lm, ld, 0, 0, 0, 0, time.UTC).Before(time.Date(ry, rm, rd, 0, 0, 0, 0, time.UTC))
	case FrequencyWeekly:
		ly, lw := last.In(loc).ISOWeek()
		ry, rw := ref.In(loc).ISOWeek()
		return ly < ry || (ly == ry && lw < rw)
	}
	return false
}

func ParseWindows(text string) ([]Window, error) {
	out := []Window{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		w, err := ParseWindow(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		out = append(out, w)
	}
	return out, nil
}

func ParseWindow(s string) (Window, error) {
	fields := strings.Fields(strings.ToLower(s))
	if len(fields) != 2 {
		return Window{}, fmt.Errorf("%q: write weekdays and times, for example \"mon-fri 22:00-06:00\"", s)
	}
	days, err := parseDays(fields[0])
	if err != nil {
		return Window{}, fmt.Errorf("%q: %w", s, err)
	}
	start, end, ok := strings.Cut(fields[1], "-")
	if !ok {
		return Window{}, fmt.Errorf("%q: times must be START-END, for example 22:00-06:00", s)
	}
	w := Window{Days: days, Start: start, End: end}
	if err := w.validate(); err != nil {
		return Window{}, fmt.Errorf("%q: %w", s, err)
	}
	return w, nil
}

func parseDay(s string) (time.Weekday, error) {
	if i := slices.Index(dayNames, s); i >= 0 {
		return time.Weekday(i), nil
	}
	return 0, fmt.Errorf("%q is not a weekday (mon, tue, wed, thu, fri, sat, sun)", s)
}

func parseDays(s string) ([]time.Weekday, error) {
	var days []time.Weekday
	for _, part := range strings.Split(s, ",") {
		a, b, isRange := strings.Cut(part, "-")
		first, err := parseDay(a)
		if err != nil {
			return nil, err
		}
		last := first
		if isRange {
			if last, err = parseDay(b); err != nil {
				return nil, err
			}
		}
		for d := first; ; d = (d + 1) % 7 {
			days = append(days, d)
			if d == last {
				break
			}
		}
	}
	slices.Sort(days)
	return slices.Compact(days), nil
}

func (w Window) String() string {
	order := []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday, time.Sunday}
	var parts []string
	for i := 0; i < len(order); {
		if !slices.Contains(w.Days, order[i]) {
			i++
			continue
		}
		j := i
		for j+1 < len(order) && slices.Contains(w.Days, order[j+1]) {
			j++
		}
		if j == i {
			parts = append(parts, dayNames[order[i]])
		} else {
			parts = append(parts, dayNames[order[i]]+"-"+dayNames[order[j]])
		}
		i = j + 1
	}
	return strings.Join(parts, ",") + " " + w.Start + "-" + w.End
}

func FormatWindows(ws []Window) string {
	lines := make([]string, len(ws))
	for i, w := range ws {
		lines[i] = w.String()
	}
	return strings.Join(lines, "\n")
}

func (f Frequency) String() string {
	switch f.Kind {
	case FrequencyInterval:
		return "every " + f.Every
	case FrequencyDaily:
		return "once a day"
	case FrequencyWeekly:
		return "once a week"
	}
	return f.Kind
}
