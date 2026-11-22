//go:build integration

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const sessTestPassword = "correct-horse-battery"

var sessTestActor = Actor{Username: "tester", Addr: "127.0.0.1"}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func createSessTestUser(t *testing.T, s *Service, username, role string) {
	t.Helper()
	if err := s.CreateUser(context.Background(), sessTestActor, username, sessTestPassword, role); err != nil {
		t.Fatalf("CreateUser(%s, %s): %v", username, role, err)
	}
}

func mustLogin(t *testing.T, s *Service, username string) Session {
	t.Helper()
	sess, err := s.Login(context.Background(), username, sessTestPassword, "192.0.2.1")
	if err != nil {
		t.Fatalf("Login(%s): %v", username, err)
	}
	return sess
}

func TestSessionTokenRandom256Bit(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "alice", RoleViewer)

	a := mustLogin(t, s, "alice")
	b := mustLogin(t, s, "alice")
	for _, sess := range []Session{a, b} {
		if len(sess.Token) != 43 {
			t.Errorf("token %q has %d chars, want 43", sess.Token, len(sess.Token))
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(sess.Token)
		if err != nil {
			t.Errorf("token %q is not unpadded base64url: %v", sess.Token, err)
		}
		if len(raw)*8 != 256 {
			t.Errorf("token decodes to %d bits, want 256", len(raw)*8)
		}
		if sess.CSRFToken == "" {
			t.Error("CSRFToken is empty")
		}
		if sess.Username != "alice" {
			t.Errorf("Username = %q, want alice", sess.Username)
		}
	}
	if a.Token == b.Token {
		t.Error("two logins returned the same token")
	}
	if a.CSRFToken == b.CSRFToken {
		t.Error("two logins returned the same CSRF token")
	}
}

func TestSessionStoredHashed(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "alice", RoleViewer)
	sess := mustLogin(t, s, "alice")
	ctx := context.Background()

	raw, err := base64.RawURLEncoding.DecodeString(sess.Token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	rows, err := s.store.Pool.Query(ctx, `SELECT to_jsonb(s)::text, token_hash FROM sessions s`)
	if err != nil {
		t.Fatalf("query sessions: %v", err)
	}
	defer rows.Close()
	want := sha256.Sum256([]byte(sess.Token))
	found := false
	n := 0
	for rows.Next() {
		n++
		var js string
		var hash []byte
		if err := rows.Scan(&js, &hash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if strings.Contains(js, sess.Token) || strings.Contains(js, hex.EncodeToString(raw)) {
			t.Errorf("sessions row contains the raw token: %s", js)
		}
		if string(hash) == string(raw) {
			t.Error("token_hash equals the raw token bytes")
		}
		if string(hash) == string(want[:]) {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if n != 1 || !found {
		t.Fatalf("got %d session rows, found sha256(token) = %v", n, found)
	}
}

func TestLookupUnknownSession(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "alice", RoleOperator)
	sess := mustLogin(t, s, "alice")
	ctx := context.Background()

	p, err := s.LookupSession(ctx, sess.Token)
	if err != nil {
		t.Fatalf("LookupSession(valid): %v", err)
	}
	if p.Username != "alice" || p.Role != RoleOperator || p.CSRFToken != sess.CSRFToken {
		t.Errorf("Principal = %+v, want alice/operator with the session's CSRF token", p)
	}
	if got, want := sortedPerms(p.Permissions), sortedPerms(wantBuiltinRoles()[RoleOperator]); !slices.Equal(got, want) {
		t.Errorf("Permissions = %v, want %v", got, want)
	}

	other, _ := randomToken()
	for _, tok := range []string{"", "garbage", other, sess.Token + "A", sess.Token[:42], strings.ToUpper(sess.Token), hex.EncodeToString([]byte(sess.Token))} {
		if _, err := s.LookupSession(ctx, tok); !errors.Is(err, ErrNoSession) {
			t.Errorf("LookupSession(%q) err = %v, want ErrNoSession", tok, err)
		}
	}
}

func TestSessionIdleExpiry(t *testing.T) {
	for _, idle := range []time.Duration{0, 10 * time.Minute} {
		clock := newTestClock()
		s := newTestService(t, Config{Now: clock.Now, IdleTimeout: idle})
		effective := idle
		if effective == 0 {
			effective = DefaultIdleTimeout
		}
		createSessTestUser(t, s, "alice", RoleViewer)
		sess := mustLogin(t, s, "alice")
		ctx := context.Background()

		clock.Advance(effective - time.Second)
		if _, err := s.LookupSession(ctx, sess.Token); err != nil {
			t.Fatalf("idle %v: lookup at login+idle-1s: %v", effective, err)
		}
		clock.Advance(effective - time.Second)
		if _, err := s.LookupSession(ctx, sess.Token); err != nil {
			t.Fatalf("idle %v: lookup did not extend the idle deadline: %v", effective, err)
		}
		clock.Advance(effective)
		if _, err := s.LookupSession(ctx, sess.Token); !errors.Is(err, ErrNoSession) {
			t.Fatalf("idle %v: lookup after idle timeout err = %v, want ErrNoSession", effective, err)
		}
		clock.Advance(-effective)
		if _, err := s.LookupSession(ctx, sess.Token); !errors.Is(err, ErrNoSession) {
			t.Fatalf("idle %v: expired session came back: %v", effective, err)
		}
	}
}

func TestSessionAbsoluteExpiry(t *testing.T) {
	clock := newTestClock()
	s := newTestService(t, Config{Now: clock.Now})
	createSessTestUser(t, s, "alice", RoleViewer)
	sess := mustLogin(t, s, "alice")
	ctx := context.Background()

	var elapsed time.Duration
	step := DefaultIdleTimeout / 2
	for elapsed+step < DefaultAbsoluteTimeout {
		clock.Advance(step)
		elapsed += step
		if _, err := s.LookupSession(ctx, sess.Token); err != nil {
			t.Fatalf("lookup at login+%v: %v", elapsed, err)
		}
	}
	clock.Advance(DefaultAbsoluteTimeout - elapsed)
	if _, err := s.LookupSession(ctx, sess.Token); !errors.Is(err, ErrNoSession) {
		t.Fatalf("lookup at login+AbsoluteTimeout err = %v, want ErrNoSession", err)
	}
}

func TestLogoutInvalidates(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "alice", RoleViewer)
	a := mustLogin(t, s, "alice")
	b := mustLogin(t, s, "alice")
	ctx := context.Background()

	if err := s.Logout(ctx, a.Token, "192.0.2.9"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := s.LookupSession(ctx, a.Token); !errors.Is(err, ErrNoSession) {
		t.Fatalf("lookup after logout err = %v, want ErrNoSession", err)
	}
	if _, err := s.LookupSession(ctx, b.Token); err != nil {
		t.Fatalf("logout of one session ended another: %v", err)
	}
	other, _ := randomToken()
	for _, tok := range []string{a.Token, other, "garbage", ""} {
		if err := s.Logout(ctx, tok, "192.0.2.9"); err != nil {
			t.Errorf("Logout(%q) = %v, want nil", tok, err)
		}
	}
}

func TestExpiredSessionsPurgedOnLogin(t *testing.T) {
	clock := newTestClock()
	s := newTestService(t, Config{Now: clock.Now})
	createSessTestUser(t, s, "alice", RoleViewer)
	mustLogin(t, s, "alice")
	clock.Advance(DefaultIdleTimeout)
	fresh := mustLogin(t, s, "alice")

	var n int
	if err := s.store.Pool.QueryRow(context.Background(), `SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("%d session rows after login, want only the fresh one", n)
	}
	if _, err := s.LookupSession(context.Background(), fresh.Token); err != nil {
		t.Fatalf("fresh session: %v", err)
	}
}

// REQ-AUTH-022 AC1: the session row keeps only a hash of the CSRF token; the token itself is never stored.
func TestCSRFTokenStoredHashed(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "alice", RoleViewer)
	sess := mustLogin(t, s, "alice")
	var raw string
	if err := s.store.Pool.QueryRow(ctx, `SELECT t::text FROM sessions t`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, sess.CSRFToken) || strings.Contains(raw, hex.EncodeToString([]byte(sess.CSRFToken))) {
		t.Fatalf("sessions row holds the CSRF token: %s", raw)
	}
	sum := sha256.Sum256([]byte(sess.CSRFToken))
	if !strings.Contains(raw, hex.EncodeToString(sum[:])) {
		t.Fatalf("sessions row %s does not hold the SHA-256 of the CSRF token", raw)
	}
	p, err := s.LookupSession(ctx, sess.Token)
	if err != nil || p.CSRFToken != sess.CSRFToken {
		t.Fatalf("LookupSession = %+v, %v; want the session's CSRF token", p, err)
	}
}
