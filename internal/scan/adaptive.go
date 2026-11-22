package scan

import (
	"math"
	"slices"
	"sync"
	"time"

	"asi/internal/inventory"
)

const (
	AdaptiveWindow       = 20
	AdaptiveSlowdown     = 2
	AdaptiveTimeoutShare = 0.10
	AdaptiveInterval     = 5 * time.Second
	AdaptiveMinBaseline  = 10 * time.Millisecond
	PauseAfterTimeouts   = 3
)

type probeSample struct {
	latency  time.Duration
	timedOut bool
}

type Controller struct {
	clock    Clock
	max      int
	floor    int
	step     int
	mu       sync.Mutex
	rate     int
	first    []time.Duration
	baseline time.Duration
	window   []probeSample
	changed  time.Time
	onChange func(rate int)
}

func NewController(maxRate int, clock Clock) *Controller {
	return newController(maxRate, 1, clock)
}

func NmapSlots(workers, maxRate, addresses int) int {
	if workers < 1 {
		workers = DefaultWorkers
	}
	return max(min(workers, maxRate/2, max(addresses, 1)), 1)
}

func MinimumRate(maxRate, slots int) int {
	maxRate = max(maxRate, 2)
	return min(max((maxRate+9)/10, 2*max(slots, 1)), maxRate)
}

func newController(maxRate, slots int, clock Clock) *Controller {
	if clock == nil {
		clock = realClock{}
	}
	maxRate = max(maxRate, 2)
	return &Controller{
		clock: clock,
		max:   maxRate,
		floor: MinimumRate(maxRate, slots),
		step:  max(maxRate/10, 1),
		rate:  maxRate,
	}
}

func (c *Controller) Rate() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rate
}

func (c *Controller) Floor() int { return c.floor }

func (c *Controller) Baseline() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.baseline
}

func (c *Controller) Observe(latency time.Duration, timedOut bool) {
	c.mu.Lock()
	rate, changed := c.observe(max(latency, 0), timedOut)
	notify := c.onChange
	c.mu.Unlock()
	if changed && notify != nil {
		notify(rate)
	}
}

func (c *Controller) observe(latency time.Duration, timedOut bool) (int, bool) {
	if c.baseline == 0 && !timedOut {
		c.first = append(c.first, latency)
		if len(c.first) == AdaptiveWindow {
			c.baseline = max(median(c.first), AdaptiveMinBaseline)
			c.first = nil
		}
	}
	c.window = append(c.window, probeSample{latency: latency, timedOut: timedOut})
	if len(c.window) > AdaptiveWindow {
		c.window = c.window[1:]
	}
	now := c.clock.Now()
	if len(c.window) < AdaptiveWindow || (!c.changed.IsZero() && now.Sub(c.changed) < AdaptiveInterval) {
		return c.rate, false
	}
	latencies := make([]time.Duration, len(c.window))
	timeouts := 0
	for i, s := range c.window {
		latencies[i] = s.latency
		if s.timedOut {
			timeouts++
		}
	}
	slow := c.baseline > 0 && median(latencies) > AdaptiveSlowdown*c.baseline
	failing := float64(timeouts)/float64(len(c.window)) > AdaptiveTimeoutShare
	next := c.rate
	switch {
	case slow || failing:
		next = max(c.rate/2, c.floor)
	case c.rate < c.max:
		next = min(c.rate+c.step, c.max)
	}
	if next == c.rate {
		return c.rate, false
	}
	c.rate, c.changed, c.window = next, now, nil
	return c.rate, true
}

func median(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	n := len(s)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

type meter struct {
	flushing   sync.Mutex
	mu         sync.Mutex
	configured int
	effective  func() int
	counts     map[time.Time]inventory.RateSample
	flushed    map[time.Time]inventory.RateSample
}

func newMeter(configured int, effective func() int) *meter {
	return &meter{configured: configured, effective: effective,
		counts: map[time.Time]inventory.RateSample{}, flushed: map[time.Time]inventory.RateSample{}}
}

func (m *meter) touch(minute time.Time, eff int, sent, packets int) {
	c := m.counts[minute]
	c.Effective = max(c.Effective, eff)
	c.Sent += sent
	c.Packets += packets
	m.counts[minute] = c
}

func (m *meter) add(t time.Time, n int) {
	eff := m.effective()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touch(t.UTC().Truncate(time.Minute), eff, n, 0)
}

func (m *meter) spread(start, end time.Time, n int) {
	if n <= 0 {
		return
	}
	eff := m.effective()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !end.After(start) {
		m.touch(end.UTC().Truncate(time.Minute), eff, 0, n)
		return
	}
	total, done := end.Sub(start).Seconds(), 0
	for minute := start.UTC().Truncate(time.Minute); minute.Before(end); minute = minute.Add(time.Minute) {
		upto := n
		if next := minute.Add(time.Minute); next.Before(end) {
			upto = int(math.Round(float64(n) * next.Sub(start).Seconds() / total))
		}
		m.touch(minute, eff, 0, upto-done)
		done = upto
	}
}

func (m *meter) mark(t time.Time) {
	eff := m.effective()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touch(t.UTC().Truncate(time.Minute), eff, 0, 0)
}

func (m *meter) pending() []inventory.RateSample {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []inventory.RateSample
	for minute, c := range m.counts {
		f := m.flushed[minute]
		out = append(out, inventory.RateSample{Minute: minute, Configured: m.configured, Effective: c.Effective,
			Sent: c.Sent - f.Sent, Packets: c.Packets - f.Packets})
	}
	slices.SortFunc(out, func(a, b inventory.RateSample) int { return a.Minute.Compare(b.Minute) })
	return out
}

func (m *meter) done(samples []inventory.RateSample) {
	m.mu.Lock()
	defer m.mu.Unlock()
	last := time.Time{}
	for _, s := range samples {
		f := m.flushed[s.Minute]
		f.Sent += s.Sent
		f.Packets += s.Packets
		m.flushed[s.Minute] = f
		last = maxTime(last, s.Minute)
	}
	for minute := range m.counts {
		if minute.Before(last) {
			delete(m.counts, minute)
			delete(m.flushed, minute)
		}
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

type RateSummary struct {
	Configured     int
	Peak           float64
	Average        float64
	Minutes        int
	Requests       int
	Packets        int
	PacketsPeak    float64
	PacketsAverage float64
}

func SummarizeRate(samples []inventory.RateSample) RateSummary {
	var s RateSummary
	for _, r := range samples {
		s.Configured = max(s.Configured, r.Configured)
		s.Peak = max(s.Peak, r.PerSecond())
		s.PacketsPeak = max(s.PacketsPeak, r.PacketsPerSecond())
		s.Requests += r.Sent
		s.Packets += r.Packets
	}
	s.Minutes = len(samples)
	if s.Minutes > 0 {
		s.Average = float64(s.Requests) / float64(60*s.Minutes)
		s.PacketsAverage = float64(s.Packets) / float64(60*s.Minutes)
	}
	return s
}
