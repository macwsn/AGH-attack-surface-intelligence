package scan

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

type Limiter struct {
	clock  Clock
	rate   float64
	burst  float64
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func NewLimiter(rate int, clock Clock) *Limiter {
	if clock == nil {
		clock = realClock{}
	}
	rate = max(rate, 1)
	return &Limiter{clock: clock, rate: float64(rate), burst: float64(rate), tokens: float64(rate), last: clock.Now()}
}

func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := l.clock.Now()
		if now.After(l.last) {
			l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
			l.last = now
		}
		if l.tokens >= 1 {
			l.tokens--
			return nil
		}
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.clock.After(max(wait, time.Nanosecond)):
		}
	}
}

type limitedTransport struct {
	limiter *Limiter
	next    http.RoundTripper
}

func (t *limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.limiter.Wait(req.Context()); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}
	return t.next.RoundTrip(req)
}
