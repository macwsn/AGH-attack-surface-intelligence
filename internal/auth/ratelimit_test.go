package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var limiterT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestLimiterAccountAndAddress(t *testing.T) {
	s := NewService(nil, Config{AccountLimit: 2, AddressLimit: 3, LimitWindow: time.Minute})
	now := limiterT0

	if !s.beginLoginAttempt("alice", "a1", now) || !s.beginLoginAttempt("alice", "a2", now) {
		t.Fatal("attempts below the account limit refused")
	}
	if s.beginLoginAttempt("alice", "a9", now) {
		t.Fatal("attempt allowed after 2 account failures")
	}
	if !s.beginLoginAttempt("bob", "a9", now) {
		t.Fatal("account limit leaked to another account")
	}

	for _, u := range []string{"u1", "u2"} {
		if !s.beginLoginAttempt(u, "addr", now) {
			t.Fatalf("%s refused below the address limit", u)
		}
	}
	if !s.beginLoginAttempt("u3", "addr", now) {
		t.Fatal("third attempt from addr refused")
	}
	if s.beginLoginAttempt("carol", "addr", now) {
		t.Fatal("attempt allowed after 3 address failures")
	}
	if !s.beginLoginAttempt("carol", "other", now) {
		t.Fatal("address limit leaked to another address")
	}
}

func TestLimiterSuccessResetsAccount(t *testing.T) {
	s := NewService(nil, Config{AccountLimit: 2, AddressLimit: 2, LimitWindow: time.Minute})
	s.beginLoginAttempt("alice", "a", limiterT0)
	s.beginLoginAttempt("alice", "b", limiterT0.Add(time.Second))
	s.loginSucceeded("alice", "b", limiterT0.Add(time.Second))
	if _, ok := s.accountFailures["alice"]; ok {
		t.Fatal("account failures kept after success")
	}
	if got := len(s.addressFailures["b"]); got != 0 {
		t.Fatalf("successful attempt still counted against its address: %d", got)
	}
	if got := len(s.addressFailures["a"]); got != 1 {
		t.Fatalf("earlier failure from another address dropped: %d", got)
	}
}

func TestLimiterAbortForgetsAttempt(t *testing.T) {
	s := NewService(nil, Config{AccountLimit: 1, AddressLimit: 1, LimitWindow: time.Minute})
	s.beginLoginAttempt("alice", "a", limiterT0)
	s.abortLoginAttempt("alice", "a", limiterT0)
	if !s.beginLoginAttempt("alice", "a", limiterT0) {
		t.Fatal("aborted attempt still counted")
	}
}

func TestLimiterWindow(t *testing.T) {
	s := NewService(nil, Config{AccountLimit: 1, LimitWindow: time.Minute})
	s.beginLoginAttempt("alice", "a", limiterT0)
	if s.beginLoginAttempt("alice", "b", limiterT0.Add(59*time.Second)) {
		t.Fatal("allowed inside the window")
	}
	if !s.beginLoginAttempt("alice", "b", limiterT0.Add(time.Minute)) {
		t.Fatal("refused once the window passed")
	}
	if got := len(s.accountFailures["alice"]); got != 1 {
		t.Fatalf("expired entries kept: %d", got)
	}
}

func TestLimiterConcurrentAttempts(t *testing.T) {
	s := NewService(nil, Config{AccountLimit: 5, AddressLimit: 100, LimitWindow: time.Minute})
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.beginLoginAttempt("alice", fmt.Sprintf("a%d", i), limiterT0) {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 5 {
		t.Fatalf("%d concurrent attempts allowed, want exactly AccountLimit=5", allowed)
	}
}

func TestLimiterPerServiceAndBounded(t *testing.T) {
	cfg := Config{AccountLimit: 1, LimitWindow: time.Minute}
	a, b := NewService(nil, cfg), NewService(nil, cfg)
	a.beginLoginAttempt("alice", "x", limiterT0)
	if !b.beginLoginAttempt("alice", "x", limiterT0) {
		t.Fatal("limiter state shared between services")
	}

	for i := range 2 * maxTrackedLoginKeys {
		a.beginLoginAttempt(fmt.Sprintf("u%d", i), fmt.Sprintf("addr%d", i), limiterT0)
	}
	a.beginLoginAttempt("fresh", "fresh", limiterT0.Add(2*time.Minute))
	if len(a.accountFailures) != 1 || len(a.addressFailures) != 1 {
		t.Fatalf("expired entries not swept: %d accounts, %d addresses", len(a.accountFailures), len(a.addressFailures))
	}
}
