package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const sessionTokenBytes = 32

func randomToken() (string, error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != sessionTokenBytes {
		return nil, false
	}
	sum := sha256.Sum256([]byte(token))
	return sum[:], true
}

func csrfFor(token string) (string, []byte) {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("asi csrf token v1"))
	csrf := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	sum := sha256.Sum256([]byte(csrf))
	return csrf, sum[:]
}

func (s *Service) createSession(ctx context.Context, userID int64, username, addr string, now time.Time) (Session, error) {
	token, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	csrf, csrfHash := csrfFor(token)
	hash, _ := hashToken(token)
	now = now.Truncate(time.Microsecond)
	err = s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := s.deleteExpiredSessions(ctx, tx, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, csrf_hash, created_at, last_used_at, address)
			VALUES ($1, $2, $3, $4, $4, $5)`, hash, userID, csrfHash, now, addr); err != nil {
			return fmt.Errorf("insert session: %w", err)
		}
		return writeAudit(ctx, tx, username, auditLogin, "", addr)
	})
	if err != nil {
		return Session{}, err
	}
	return Session{Token: token, CSRFToken: csrf, Username: username, CreatedAt: now}, nil
}

func (s *Service) deleteExpiredSessions(ctx context.Context, tx pgx.Tx, now time.Time) error {
	if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE last_used_at <= $1 OR created_at <= $2`,
		now.Add(-s.cfg.IdleTimeout), now.Add(-s.cfg.AbsoluteTimeout)); err != nil {
		return fmt.Errorf("delete expired sessions: %w", err)
	}
	return nil
}

func (s *Service) LookupSession(ctx context.Context, token string) (Principal, error) {
	hash, ok := hashToken(token)
	if !ok {
		return Principal{}, ErrNoSession
	}
	now := s.cfg.Now().Truncate(time.Microsecond)
	var p Principal
	expired := false
	err := s.store.Tx(ctx, func(tx pgx.Tx) error {
		var (
			created, lastUsed time.Time
			storedCSRF        []byte
		)
		err := tx.QueryRow(ctx, `SELECT s.created_at, s.last_used_at, s.csrf_hash, u.username, u.role
			FROM sessions s JOIN users u ON u.id = s.user_id
			WHERE s.token_hash = $1 AND NOT u.disabled FOR UPDATE OF s`, hash).
			Scan(&created, &lastUsed, &storedCSRF, &p.Username, &p.Role)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSession
		}
		if err != nil {
			return fmt.Errorf("look up session: %w", err)
		}
		csrf, csrfHash := csrfFor(token)
		if !hmac.Equal(csrfHash, storedCSRF) {
			return ErrNoSession
		}
		p.CSRFToken = csrf
		if !now.Before(lastUsed.Add(s.cfg.IdleTimeout)) || !now.Before(created.Add(s.cfg.AbsoluteTimeout)) {
			if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, hash); err != nil {
				return fmt.Errorf("delete expired session: %w", err)
			}
			expired = true
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE sessions SET last_used_at = $2 WHERE token_hash = $1`, hash, now); err != nil {
			return fmt.Errorf("extend session: %w", err)
		}
		rows, err := tx.Query(ctx, `SELECT permission FROM role_permissions WHERE role = $1 ORDER BY permission`, p.Role)
		if err != nil {
			return fmt.Errorf("load permissions: %w", err)
		}
		p.Permissions, err = pgx.CollectRows(rows, pgx.RowTo[Permission])
		if err != nil {
			return fmt.Errorf("load permissions: %w", err)
		}
		return nil
	})
	if err != nil {
		return Principal{}, err
	}
	if expired {
		return Principal{}, ErrNoSession
	}
	return p, nil
}
