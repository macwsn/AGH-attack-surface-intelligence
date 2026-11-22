package inventory

const (
	AvailabilityAlpha   = 0.3
	AvailabilityInitial = 0.5
	PeriodicMinSamples  = 6
	UsuallyUp           = 0.8
	UsuallyDown         = 0.2
	ExpectedUp          = "up"
	ExpectedDown        = "down"
)

type HourObservation struct {
	Hour int
	Seen bool
}

type Availability struct {
	Hours   [24]float64
	Samples int
}

func NewAvailability() Availability {
	var a Availability
	for h := range a.Hours {
		a.Hours[h] = AvailabilityInitial
	}
	return a
}

func BuildAvailability(obs []HourObservation) Availability {
	a := NewAvailability()
	for _, o := range obs {
		a = a.Observe(o.Hour, o.Seen)
	}
	return a
}

func (a Availability) Observe(hour int, seen bool) Availability {
	if hour < 0 || hour > 23 {
		return a
	}
	x := 0.0
	if seen {
		x = 1
	}
	a.Hours[hour] += AvailabilityAlpha * (x - a.Hours[hour])
	a.Samples++
	return a
}

func (a Availability) Periodic() bool {
	if a.Samples < PeriodicMinSamples {
		return false
	}
	high, low := false, false
	for _, v := range a.Hours {
		high = high || v >= UsuallyUp
		low = low || v <= UsuallyDown
	}
	return high && low
}

func (a Availability) UsualHours() []int {
	out := []int{}
	if !a.Periodic() {
		return out
	}
	for h, v := range a.Hours {
		if v >= UsuallyUp {
			out = append(out, h)
		}
	}
	return out
}

func (a Availability) Expected(hour int) string {
	if !a.Periodic() || hour < 0 || hour > 23 {
		return ""
	}
	switch v := a.Hours[hour]; {
	case v >= UsuallyUp:
		return ExpectedUp
	case v <= UsuallyDown:
		return ExpectedDown
	}
	return ""
}

func (a Availability) Export() *ExportAvailability {
	if a.Samples == 0 {
		return nil
	}
	return &ExportAvailability{
		Hours:      append([]float64(nil), a.Hours[:]...),
		Samples:    a.Samples,
		Periodic:   a.Periodic(),
		UsualHours: a.UsualHours(),
	}
}

func (e *ExportAvailability) Profile() Availability {
	a := NewAvailability()
	if e == nil {
		return a
	}
	copy(a.Hours[:], e.Hours)
	a.Samples = e.Samples
	return a
}

type coverage struct {
	run      int64
	hour     int
	seen     bool
	external bool
}

type hostRhythm struct {
	seen     []bool
	ignored  map[int64]bool
	profile  Availability
	expected string
}

func applyRhythm(cov []coverage, asOf int64) hostRhythm {
	r := hostRhythm{seen: make([]bool, 0, len(cov)), ignored: map[int64]bool{}, profile: NewAvailability()}
	for _, c := range cov {
		exp := r.profile.Expected(c.hour)
		if c.run == asOf {
			r.expected = exp
		}
		if !c.seen && exp == ExpectedDown {
			r.ignored[c.run] = true
		} else {
			r.seen = append(r.seen, c.seen)
		}
		if !c.external {
			r.profile = r.profile.Observe(c.hour, c.seen)
		}
	}
	return r
}
