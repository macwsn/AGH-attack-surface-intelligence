package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
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
	rate   atomic.Int64
	mu     sync.Mutex
	tokens float64
	last   time.Time
	minute time.Time
	used   int64
}

func NewLimiter(rate int, clock Clock) *Limiter {
	if clock == nil {
		clock = realClock{}
	}
	rate = max(rate, 1)
	l := &Limiter{clock: clock, tokens: float64(rate), last: clock.Now()}
	l.SetRate(rate)
	return l
}

func (l *Limiter) SetRate(rate int) {
	l.rate.Store(int64(max(rate, 1)))
}

func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		perSecond := l.rate.Load()
		rate := float64(perSecond)
		now := l.clock.Now()
		if now.After(l.last) {
			l.tokens = min(rate, l.tokens+now.Sub(l.last).Seconds()*rate)
			l.last = now
		}
		if minute := now.UTC().Truncate(time.Minute); !minute.Equal(l.minute) {
			l.minute, l.used = minute, 0
		}
		var wait time.Duration
		switch {
		case l.used >= 60*perSecond:
			wait = l.minute.Add(time.Minute).Sub(now)
		case l.tokens >= 1:
			l.tokens--
			l.used++
			return nil
		default:
			wait = time.Duration((1 - l.tokens) / rate * float64(time.Second))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.clock.After(max(wait, time.Nanosecond)):
		}
	}
}

type limitedTransport struct {
	limiter *Limiter
	clock   Clock
	sent    func(t time.Time)
	observe func(d time.Duration, timedOut bool)
	next    http.RoundTripper
	packets *atomic.Int64
}

func (t *limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.limiter.Wait(req.Context()); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}
	t.sent(t.clock.Now())
	if t.packets != nil {
		t.packets.Add(1)
	}
	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		t.observe(time.Since(start), isTimeout(err))
		return nil, err
	}
	resp.Body = &observedBody{ReadCloser: resp.Body, done: func(err error) {
		t.observe(time.Since(start), isTimeout(err))
	}}
	return resp, nil
}

type observedBody struct {
	io.ReadCloser
	done func(err error)
	once sync.Once
	err  error
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		b.err = err
	}
	return n, err
}

func (b *observedBody) Close() error {
	b.once.Do(func() { b.done(b.err) })
	return b.ReadCloser.Close()
}

func isTimeout(err error) bool {
	var ne net.Error
	return err != nil && (errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout())
}
