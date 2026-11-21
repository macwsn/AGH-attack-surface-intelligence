//go:build integration

package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

func failLogin(t *testing.T, s *Service, username, addr string) {
	t.Helper()
	_, err := s.Login(context.Background(), username, "wrong-password-123", addr)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login(%s, wrong, %s) err = %v, want ErrInvalidCredentials", username, addr, err)
	}
}

func TestLoginRateLimitPerAccount(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "alice", RoleViewer)
	ctx := context.Background()

	for i := range DefaultAccountLimit {
		failLogin(t, s, "alice", fmt.Sprintf("198.51.100.%d", i))
	}
	if _, err := s.Login(ctx, "alice", sessTestPassword, "203.0.113.7"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("correct login after %d failures err = %v, want ErrRateLimited", DefaultAccountLimit, err)
	}
}

func TestLoginSuccessResetsAccountFailures(t *testing.T) {
	s := newTestService(t, Config{AccountLimit: 3})
	createSessTestUser(t, s, "alice", RoleViewer)

	for range 2 {
		failLogin(t, s, "alice", "198.51.100.1")
		failLogin(t, s, "alice", "198.51.100.1")
		mustLogin(t, s, "alice")
	}
}

func TestLoginRateLimitNonexistentAccount(t *testing.T) {
	s := newTestService(t, Config{})
	ctx := context.Background()

	for i := range DefaultAccountLimit {
		failLogin(t, s, "ghost", fmt.Sprintf("198.51.100.%d", i))
	}
	if _, err := s.Login(ctx, "ghost", sessTestPassword, "203.0.113.7"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("login of nonexistent user after %d failures err = %v, want ErrRateLimited", DefaultAccountLimit, err)
	}
}

func TestLoginRateLimitWindowExpires(t *testing.T) {
	clock := newTestClock()
	s := newTestService(t, Config{Now: clock.Now})
	createSessTestUser(t, s, "alice", RoleViewer)
	ctx := context.Background()

	for range DefaultAccountLimit {
		failLogin(t, s, "alice", "198.51.100.1")
	}
	clock.Advance(DefaultLimitWindow - time.Second)
	if _, err := s.Login(ctx, "alice", sessTestPassword, "198.51.100.1"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("login inside the window err = %v, want ErrRateLimited", err)
	}
	clock.Advance(2 * time.Second)
	if _, err := s.Login(ctx, "alice", sessTestPassword, "198.51.100.1"); err != nil {
		t.Fatalf("login after the window: %v", err)
	}
}

func TestLoginRateLimitPerAddress(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "alice", RoleViewer)
	ctx := context.Background()

	for i := range DefaultAddressLimit {
		failLogin(t, s, fmt.Sprintf("user%02d", i), "198.51.100.1")
	}
	if _, err := s.Login(ctx, "alice", sessTestPassword, "198.51.100.1"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("login from the limited address err = %v, want ErrRateLimited", err)
	}
	if _, err := s.Login(ctx, "alice", sessTestPassword, "198.51.100.2"); err != nil {
		t.Fatalf("login from another address: %v", err)
	}
}

func TestLoginFailureIndistinguishable(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "alice", RoleViewer)
	ctx := context.Background()

	_, errWrong := s.Login(ctx, "alice", "wrong-password-123", "198.51.100.1")
	_, errGhost := s.Login(ctx, "ghost", "wrong-password-123", "198.51.100.1")
	_, errGhostSame := s.Login(ctx, "ghost2", sessTestPassword, "198.51.100.1")
	for _, err := range []error{errWrong, errGhost, errGhostSame} {
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("err = %v, want ErrInvalidCredentials", err)
		}
	}
	if errWrong.Error() != errGhost.Error() || errGhost.Error() != errGhostSame.Error() {
		t.Fatalf("error texts differ: %q / %q / %q", errWrong, errGhost, errGhostSame)
	}
}

func TestLoginNonexistentUserCostsHash(t *testing.T) {
	s := newTestService(t, Config{AccountLimit: 100, AddressLimit: 100})
	createSessTestUser(t, s, "alice", RoleViewer)
	ctx := context.Background()

	median := func(username string) time.Duration {
		var d []time.Duration
		for range 3 {
			start := time.Now()
			if _, err := s.Login(ctx, username, "wrong-password-123", "198.51.100.1"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login(%s) err = %v", username, err)
			}
			d = append(d, time.Since(start))
		}
		slices.Sort(d)
		return d[1]
	}
	existing := median("alice")
	missing := median("ghost")
	if missing*2 < existing {
		t.Fatalf("nonexistent-user login median %v < 50%% of existing-user median %v", missing, existing)
	}
}
