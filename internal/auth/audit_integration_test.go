//go:build integration

package auth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type auditRow struct {
	ID      int64
	At      time.Time
	Actor   string
	Action  string
	Target  string
	Address string
}

func lastAuditID(t *testing.T, s *Service) int64 {
	t.Helper()
	var id int64
	if err := s.store.Pool.QueryRow(context.Background(), `SELECT coalesce(max(id), 0) FROM audit_log`).Scan(&id); err != nil {
		t.Fatalf("max audit id: %v", err)
	}
	return id
}

func auditSince(t *testing.T, s *Service, after int64) []auditRow {
	t.Helper()
	rows, err := s.store.Pool.Query(context.Background(),
		`SELECT id, at, actor, action, target, address FROM audit_log WHERE id > $1 ORDER BY id`, after)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[auditRow])
	if err != nil {
		t.Fatalf("collect audit_log: %v", err)
	}
	return out
}

func dbNow(t *testing.T, s *Service) time.Time {
	t.Helper()
	var now time.Time
	if err := s.store.Pool.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatalf("clock_timestamp: %v", err)
	}
	return now
}

func expectAudit(t *testing.T, s *Service, want auditRow, op func()) {
	t.Helper()
	before := lastAuditID(t, s)
	start := dbNow(t, s)
	op()
	end := dbNow(t, s)
	got := auditSince(t, s, before)
	if len(got) != 1 {
		t.Fatalf("%s: %d audit rows added, want 1: %+v", want.Action, len(got), got)
	}
	r := got[0]
	if r.Actor != want.Actor || r.Action != want.Action || r.Target != want.Target || r.Address != want.Address {
		t.Fatalf("audit row = %+v, want %+v", r, want)
	}
	if r.At.Before(start) || r.At.After(end) {
		t.Fatalf("%s: at %v outside call [%v, %v]", want.Action, r.At, start, end)
	}
}

func TestAuditLoginLogout(t *testing.T) {
	s := newTestService(t, Config{})
	createSessTestUser(t, s, "alice", RoleViewer)
	ctx := context.Background()

	var sess Session
	expectAudit(t, s, auditRow{Actor: "alice", Action: "login", Address: "192.0.2.10"}, func() {
		var err error
		sess, err = s.Login(ctx, "alice", sessTestPassword, "192.0.2.10")
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
	})
	expectAudit(t, s, auditRow{Actor: "alice", Action: "logout", Address: "192.0.2.11"}, func() {
		if err := s.Logout(ctx, sess.Token, "192.0.2.11"); err != nil {
			t.Fatalf("Logout: %v", err)
		}
	})
	before := lastAuditID(t, s)
	if err := s.Logout(ctx, sess.Token, "192.0.2.11"); err != nil {
		t.Fatalf("second Logout: %v", err)
	}
	if got := auditSince(t, s, before); len(got) != 0 {
		t.Fatalf("logout of an unknown session added audit rows %+v", got)
	}
}

func TestAuditFailedLogin(t *testing.T) {
	s := newTestService(t, Config{AccountLimit: 2})
	createSessTestUser(t, s, "alice", RoleViewer)
	ctx := context.Background()

	for _, c := range []struct{ user, password string }{
		{"alice", "wrong-password-123"},
		{"ghost", "wrong-password-123"},
		{"alice", "wrong-password-456"},
		{"alice", sessTestPassword},
	} {
		expectAudit(t, s, auditRow{Actor: c.user, Action: "login_failed", Address: "198.51.100.3"}, func() {
			_, err := s.Login(ctx, c.user, c.password, "198.51.100.3")
			if !errors.Is(err, ErrInvalidCredentials) && !errors.Is(err, ErrRateLimited) {
				t.Fatalf("Login(%s) err = %v, want invalid credentials or rate limited", c.user, err)
			}
		})
	}
}

func TestAuditNoSecrets(t *testing.T) {
	s := newTestService(t, Config{AccountLimit: 1})
	ctx := context.Background()
	actor := Actor{Username: "root", Addr: "192.0.2.40"}
	if err := s.CreateUser(ctx, actor, "alice", sessTestPassword, RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	sess, err := s.Login(ctx, "alice", sessTestPassword, "192.0.2.41")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := s.Login(ctx, "alice", "wrong-password-xyz", "192.0.2.41"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login(wrong) err = %v", err)
	}
	if _, err := s.Login(ctx, "alice", "rate-limited-password", "192.0.2.41"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Login(limited) err = %v", err)
	}
	if err := s.Logout(ctx, sess.Token, "192.0.2.41"); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	raw, _ := base64.RawURLEncoding.DecodeString(sess.Token)
	secrets := []string{sessTestPassword, "wrong-password-xyz", "rate-limited-password", sess.Token, sess.CSRFToken, hex.EncodeToString(raw)}
	rows := auditSince(t, s, 0)
	if len(rows) < 5 {
		t.Fatalf("got %d audit rows, want at least 5", len(rows))
	}
	for _, r := range rows {
		line := strings.Join([]string{r.Actor, r.Action, r.Target, r.Address}, "|")
		for _, sec := range secrets {
			if strings.Contains(line, sec) {
				t.Errorf("audit row %q contains secret %q", line, sec)
			}
		}
	}
}
