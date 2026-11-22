package web

import "time"

const (
	zonedLayout        = "2006-01-02 15:04 MST"
	zonedSecondsLayout = "2006-01-02 15:04:05 MST"
	dateLayout         = "2006-01-02"
)

func zonedTime(t time.Time, loc *time.Location) string {
	return zonedFormat(t, loc, zonedLayout)
}

func zonedFormat(t time.Time, loc *time.Location, layout string) string {
	if t.IsZero() {
		return ""
	}
	if loc == nil {
		loc = time.Local
	}
	return t.In(loc).Format(layout)
}

func zoneOf(timezone string) *time.Location {
	if timezone == "" {
		return nil
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil
	}
	return loc
}
