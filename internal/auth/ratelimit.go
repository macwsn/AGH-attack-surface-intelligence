package auth

import "time"

const maxTrackedLoginKeys = 1024

func (s *Service) beginLoginAttempt(username, addr string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recentFailures(s.accountFailures, username, now) >= s.cfg.AccountLimit ||
		s.recentFailures(s.addressFailures, addr, now) >= s.cfg.AddressLimit {
		return false
	}
	s.accountFailures[username] = append(s.accountFailures[username], now)
	s.addressFailures[addr] = append(s.addressFailures[addr], now)
	s.sweep(s.accountFailures, now)
	s.sweep(s.addressFailures, now)
	return true
}

func (s *Service) loginSucceeded(username, addr string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accountFailures, username)
	forgetAttempt(s.addressFailures, addr, now)
}

func (s *Service) abortLoginAttempt(username, addr string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	forgetAttempt(s.accountFailures, username, now)
	forgetAttempt(s.addressFailures, addr, now)
}

func forgetAttempt(m map[string][]time.Time, key string, at time.Time) {
	times := m[key]
	for i := len(times) - 1; i >= 0; i-- {
		if times[i].Equal(at) {
			times = append(times[:i:i], times[i+1:]...)
			break
		}
	}
	if len(times) == 0 {
		delete(m, key)
		return
	}
	m[key] = times
}

func (s *Service) recentFailures(m map[string][]time.Time, key string, now time.Time) int {
	times := m[key]
	cutoff := now.Add(-s.cfg.LimitWindow)
	i := 0
	for i < len(times) && !times[i].After(cutoff) {
		i++
	}
	if i == len(times) {
		delete(m, key)
		return 0
	}
	m[key] = times[i:]
	return len(times) - i
}

func (s *Service) sweep(m map[string][]time.Time, now time.Time) {
	if len(m) <= maxTrackedLoginKeys {
		return
	}
	for key := range m {
		s.recentFailures(m, key, now)
	}
}
