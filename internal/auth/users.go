package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const adminLockKey int64 = 0x6173692d61646d6e

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

func isPgError(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}

func (s *Service) CreateUser(ctx context.Context, actor Actor, username, password, role string) error {
	if strings.TrimSpace(username) == "" {
		return errors.New("create user: username must not be empty")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("create user %q: %w", username, err)
	}
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)`, username, hash, role)
		switch {
		case isPgError(err, pgUniqueViolation):
			return fmt.Errorf("%w: %q", ErrUserExists, username)
		case isPgError(err, pgForeignKeyViolation):
			return fmt.Errorf("%w: %q", ErrUnknownRole, role)
		case err != nil:
			return fmt.Errorf("create user %q: %w", username, err)
		}
		return writeAudit(ctx, tx, actor.Username, auditUserCreate, username, actor.Addr)
	})
}

func (s *Service) GetUser(ctx context.Context, username string) (User, error) {
	u := User{Username: username}
	err := s.store.Pool.QueryRow(ctx, `SELECT role, created_at FROM users WHERE username = $1`, username).Scan(&u.Role, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}
	if err != nil {
		return User{}, fmt.Errorf("get user %q: %w", username, err)
	}
	return u, nil
}

func (s *Service) SetUserRole(ctx context.Context, actor Actor, username, role string) error {
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		current, err := lockUserForAdminChange(ctx, tx, username)
		if err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM roles WHERE name = $1)`, role).Scan(&exists); err != nil {
			return fmt.Errorf("check role %q: %w", role, err)
		}
		if !exists {
			return fmt.Errorf("%w: %q", ErrUnknownRole, role)
		}
		if current == RoleAdmin && role != RoleAdmin {
			if err := ensureOtherAdmin(ctx, tx); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE users SET role = $2, updated_at = now() WHERE username = $1`, username, role)
		if isPgError(err, pgForeignKeyViolation) {
			return fmt.Errorf("%w: %q", ErrUnknownRole, role)
		}
		if err != nil {
			return fmt.Errorf("set role of %q: %w", username, err)
		}
		return writeAudit(ctx, tx, actor.Username, auditUserUpdate, username, actor.Addr)
	})
}

func (s *Service) DeleteUser(ctx context.Context, actor Actor, username string) error {
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		current, err := lockUserForAdminChange(ctx, tx, username)
		if err != nil {
			return err
		}
		if current == RoleAdmin {
			if err := ensureOtherAdmin(ctx, tx); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE username = $1`, username); err != nil {
			return fmt.Errorf("delete user %q: %w", username, err)
		}
		return writeAudit(ctx, tx, actor.Username, auditUserDelete, username, actor.Addr)
	})
}

func lockUserForAdminChange(ctx context.Context, tx pgx.Tx, username string) (string, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, adminLockKey); err != nil {
		return "", fmt.Errorf("lock admin set: %w", err)
	}
	var role string
	err := tx.QueryRow(ctx, `SELECT role FROM users WHERE username = $1 FOR UPDATE`, username).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}
	if err != nil {
		return "", fmt.Errorf("load user %q: %w", username, err)
	}
	return role, nil
}

func ensureOtherAdmin(ctx context.Context, tx pgx.Tx) error {
	var admins int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = $1`, RoleAdmin).Scan(&admins); err != nil {
		return fmt.Errorf("count admins: %w", err)
	}
	if admins <= 1 {
		return ErrLastAdmin
	}
	return nil
}
