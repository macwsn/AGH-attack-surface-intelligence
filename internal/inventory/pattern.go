package inventory

import (
	"fmt"
	"sort"
	"time"
)

const MinPatternRuns = 6

type PresenceObservation struct {
	At      time.Time
	Covered bool
	Seen    bool
}

type Pattern struct {
	Start int
	End   int
}

func (p Pattern) Label() string {
	return fmt.Sprintf("%02d:00-%02d:00", p.Start, p.End%24)
}

func (p Pattern) contains(hour int) bool {
	length := (p.End - p.Start + 24) % 24
	return length == 0 || (hour-p.Start+24)%24 < length
}

func TimeOfDay(obs []PresenceObservation, loc *time.Location) (Pattern, bool) {
	if loc == nil {
		loc = time.UTC
	}
	var seen, missed [24]bool
	covering := 0
	for _, o := range obs {
		if !o.Covered {
			continue
		}
		covering++
		h := o.At.In(loc).Hour()
		if o.Seen {
			seen[h] = true
		} else {
			missed[h] = true
		}
	}
	if covering < MinPatternRuns {
		return Pattern{}, false
	}
	var hours []int
	anyMissed := false
	for h := 0; h < 24; h++ {
		if seen[h] {
			hours = append(hours, h)
		}
		anyMissed = anyMissed || missed[h]
	}
	if len(hours) == 0 || !anyMissed {
		return Pattern{}, false
	}
	sort.Ints(hours)
	gapAfter, gap := len(hours)-1, hours[0]+24-hours[len(hours)-1]
	for i := 0; i+1 < len(hours); i++ {
		if g := hours[i+1] - hours[i]; g > gap {
			gapAfter, gap = i, g
		}
	}
	p := Pattern{Start: hours[(gapAfter+1)%len(hours)], End: (hours[gapAfter] + 1) % 24}
	for h := 0; h < 24; h++ {
		if missed[h] && p.contains(h) {
			return Pattern{}, false
		}
	}
	return p, true
}
