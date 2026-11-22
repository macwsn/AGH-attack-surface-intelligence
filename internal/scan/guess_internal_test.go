package scan

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan/nmap/nmaptest"
	"asi/internal/scan/scantest"
)

type hangingTransport struct{}

func (hangingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, r.Context().Err()
}

type bubble struct{}

func (bubble) Now() time.Time                         { return time.Now() }
func (bubble) After(d time.Duration) <-chan time.Time { return time.After(d) }

// REQ-SCAN-018 REQ-SCAN-019
func TestGuessedProbeTimeoutsStayOutOfControllerAndHostPause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hang := func(string) http.RoundTripper { return hangingTransport{} }
		s := &Scanner{Store: &scantest.Store{}, Runner: &nmaptest.Runner{}, Clock: bubble{}, Transport: hang}
		run := inventory.Run{Name: "g", Status: inventory.RunRunning,
			Settings: inventory.RunSettings{Targets: []string{"10.0.0.1"}, Ports: []int{7001}, MaxRate: 1000}}
		r, err := s.prepare(context.Background(), run, &atomic.Int64{})
		if err != nil {
			t.Fatal(err)
		}
		attempt := func(guess bool, schemes []bool, guard *hostGuard) time.Duration {
			svc := inventory.ServiceResult{Port: 7001}
			start := time.Now()
			r.probe(context.Background(), &svc, "10.0.0.1", "", schemes, guess, guard)
			return time.Since(start)
		}

		guard := &hostGuard{}
		for range 2 * AdaptiveWindow {
			if d := attempt(true, []bool{false, true}, guard); d > GuessTimeout {
				t.Fatalf("guessed probe held %s, want at most %s", d, GuessTimeout)
			}
		}
		if r.ctrl.Rate() != 1000 || len(r.ctrl.window) != 0 {
			t.Errorf("after %d guessed timeouts: rate %d, controller window %d, want 1000 and no samples", 2*AdaptiveWindow, r.ctrl.Rate(), len(r.ctrl.window))
		}
		if guard.timeouts != 0 || guard.isPaused() {
			t.Errorf("after guessed timeouts: host count %d paused %t, want 0 and not paused", guard.timeouts, guard.isPaused())
		}

		control := &hostGuard{}
		attempt(false, []bool{false}, control)
		for range AdaptiveWindow {
			attempt(false, []bool{false}, &hostGuard{})
		}
		if control.timeouts != 1 || r.ctrl.Rate() >= 1000 {
			t.Errorf("control: identified HTTP timeouts gave host count %d and rate %d, want 1 and a lower rate", control.timeouts, r.ctrl.Rate())
		}
	})
}

// REQ-SCAN-018 REQ-SCAN-021
func TestRecheckFloorMatchesPlan(t *testing.T) {
	st := &scantest.Store{Known: []inventory.KnownService{{Address: "10.0.0.5", Port: 80, Protocol: "tcp", Service: "http", HTTP: true}}}
	s := &Scanner{Store: st, Runner: &nmaptest.Runner{}, Clock: scantest.NewClock(time.Unix(0, 0)), Transport: (&scantest.Transport{}).For}
	settings := inventory.RunSettings{Targets: []string{"10.0.0.0/24"}, Ports: []int{80}, MaxRate: 10, Workers: 4, Mode: inventory.ModeRecheck}
	p, err := s.Plan(context.Background(), settings)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.prepare(context.Background(), inventory.Run{Name: "re", Status: inventory.RunRunning, Settings: settings}, &atomic.Int64{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Slots != 1 || p.MinRate != 2 || r.slots != p.Slots || r.ctrl.Floor() != p.MinRate {
		t.Fatalf("plan slots=%d min rate=%d; run slots=%d floor=%d: want 1 slot and 2 per second in both", p.Slots, p.MinRate, r.slots, r.ctrl.Floor())
	}
}
