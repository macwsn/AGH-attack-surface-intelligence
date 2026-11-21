package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func (s *Service) Login(ctx context.Context, username, password, addr string) (Session, error) {
	now := s.cfg.Now()
	if !s.beginLoginAttempt(username, addr, now) {
		if err := writeAudit(ctx, s.store.Pool, username, auditLoginFailed, "", addr); err != nil {
			return Session{}, err
		}
		return Session{}, ErrRateLimited
	}
	userID, ok, err := s.checkCredentials(ctx, username, password)
	if err != nil {
		s.abortLoginAttempt(username, addr, now)
		return Session{}, err
	}
	if !ok {
		if err := writeAudit(ctx, s.store.Pool, username, auditLoginFailed, "", addr); err != nil {
			return Session{}, err
		}
		return Session{}, ErrInvalidCredentials
	}
	s.loginSucceeded(username, addr, now)
	return s.createSession(ctx, userID, username, addr, now)
}

func (s *Service) checkCredentials(ctx context.Context, username, password string) (int64, bool, error) {
	var userID int64
	encoded := s.dummyHash
	err := s.store.Pool.QueryRow(ctx, `SELECT id, password_hash FROM users WHERE username = $1`, username).
		Scan(&userID, &encoded)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, false, fmt.Errorf("look up user: %w", err)
	}
	ok, err := VerifyPassword(encoded, password)
	if err != nil {
		return 0, false, fmt.Errorf("verify password: %w", err)
	}
	return userID, found && ok, nil
}

func (s *Service) Logout(ctx context.Context, token, addr string) error {
	hash, ok := hashToken(token)
	if !ok {
		return nil
	}
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		var username string
		err := tx.QueryRow(ctx, `DELETE FROM sessions s USING users u
			WHERE s.user_id = u.id AND s.token_hash = $1 RETURNING u.username`, hash).Scan(&username)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("delete session: %w", err)
		}
		return writeAudit(ctx, tx, username, auditLogout, "", addr)
	})
}
