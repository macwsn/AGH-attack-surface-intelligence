package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const adminLockKey int64 = 0x6173692d61646d6e

var (
	ErrOwnAccount   = errors.New("the actor cannot reset the password of, disable or delete their own account")
	ErrStrongerUser = errors.New("the target user's role has a permission the actor's role does not hold")
)

const holdsAllPermissions = `NOT EXISTS (SELECT 1 FROM permissions p WHERE NOT EXISTS
	(SELECT 1 FROM role_permissions rp WHERE rp.role = %s AND rp.permission = p.name))`

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
		if err := checkActorMayAssign(ctx, tx, actor, "", role); err != nil {
			return err
		}
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
	err := s.store.Pool.QueryRow(ctx, `SELECT role, disabled, created_at FROM users WHERE username = $1`, username).
		Scan(&u.Role, &u.Disabled, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}
	if err != nil {
		return User{}, fmt.Errorf("get user %q: %w", username, err)
	}
	return u, nil
}

func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.store.Pool.Query(ctx, `SELECT username, role, disabled, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	users, err := pgx.CollectRows(rows, pgx.RowToStructByPos[User])
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

func (s *Service) ResetPassword(ctx context.Context, actor Actor, username, password string) error {
	return s.ResetPasswordKeepSession(ctx, actor, username, password, "")
}

func (s *Service) ResetPasswordKeepSession(ctx context.Context, actor Actor, username, password, session string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("reset password of %q: %w", username, err)
	}
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		current, err := lockUserForAdminChange(ctx, tx, username)
		if err != nil {
			return err
		}
		if err := checkActorMayActOn(ctx, tx, actor, username, current.role, true); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, current.id, hash); err != nil {
			return fmt.Errorf("reset password of %q: %w", username, err)
		}
		var keep []byte
		if actor.Username == username {
			keep, _ = hashToken(session)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token_hash IS DISTINCT FROM $2`, current.id, keep); err != nil {
			return fmt.Errorf("end sessions of %q: %w", username, err)
		}
		return writeAudit(ctx, tx, actor.Username, auditUserPass, username, actor.Addr)
	})
}

func (s *Service) ChangePassword(ctx context.Context, actor Actor, current, password, session string) error {
	keep, ok := hashToken(session)
	if !ok {
		return ErrNoSession
	}
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	now := s.cfg.Now()
	if !s.beginLoginAttempt(actor.Username, actor.Addr, now) {
		if err := writeAudit(ctx, s.store.Pool, actor.Username, auditLoginFailed, "", actor.Addr); err != nil {
			return err
		}
		return ErrRateLimited
	}
	id, ok, err := s.checkCredentials(ctx, actor.Username, current)
	if err != nil {
		s.abortLoginAttempt(actor.Username, actor.Addr, now)
		return err
	}
	if !ok {
		if err := writeAudit(ctx, s.store.Pool, actor.Username, auditLoginFailed, "", actor.Addr); err != nil {
			return err
		}
		return ErrInvalidCredentials
	}
	s.loginSucceeded(actor.Username, actor.Addr, now)
	if current == password {
		return ErrSamePassword
	}
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("change password of %q: %w", actor.Username, err)
	}
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, id, hash); err != nil {
			return fmt.Errorf("change password of %q: %w", actor.Username, err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`, id, keep); err != nil {
			return fmt.Errorf("end other sessions of %q: %w", actor.Username, err)
		}
		return writeAudit(ctx, tx, actor.Username, auditUserPass, actor.Username, actor.Addr)
	})
}

func (s *Service) SetUserDisabled(ctx context.Context, actor Actor, username string, disabled bool) error {
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		current, err := lockUserForAdminChange(ctx, tx, username)
		if err != nil {
			return err
		}
		if disabled && current.enabledAdmin() {
			if err := ensureOtherAdmin(ctx, tx); err != nil {
				return err
			}
		}
		if err := checkActorMayActOn(ctx, tx, actor, username, current.role, true); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET disabled = $2, updated_at = now() WHERE id = $1`, current.id, disabled); err != nil {
			return fmt.Errorf("set disabled of %q: %w", username, err)
		}
		action := auditUserEnable
		if disabled {
			action = auditUserDisable
			if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, current.id); err != nil {
				return fmt.Errorf("end sessions of %q: %w", username, err)
			}
		}
		return writeAudit(ctx, tx, actor.Username, action, username, actor.Addr)
	})
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
		if current.enabledAdmin() {
			all, err := roleHoldsAllPermissions(ctx, tx, role)
			if err != nil {
				return err
			}
			if !all {
				if err := ensureOtherAdmin(ctx, tx); err != nil {
					return err
				}
			}
		}
		if err := checkActorMayAssign(ctx, tx, actor, username, role); err != nil {
			return err
		}
		if err := checkActorMayActOn(ctx, tx, actor, username, current.role, false); err != nil {
			return err
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
		if current.enabledAdmin() {
			if err := ensureOtherAdmin(ctx, tx); err != nil {
				return err
			}
		}
		if err := checkActorMayActOn(ctx, tx, actor, username, current.role, true); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE username = $1`, username); err != nil {
			return fmt.Errorf("delete user %q: %w", username, err)
		}
		return writeAudit(ctx, tx, actor.Username, auditUserDelete, username, actor.Addr)
	})
}

type lockedUser struct {
	id       int64
	role     string
	disabled bool
	allPerms bool
}

func (u lockedUser) enabledAdmin() bool {
	return u.allPerms && !u.disabled
}

func checkActorMayActOn(ctx context.Context, tx pgx.Tx, actor Actor, username, role string, refuseSelf bool) error {
	a, ok, err := lookupActorRole(ctx, tx, actor)
	if err != nil || !ok {
		return err
	}
	if refuseSelf && actor.Username == username {
		return fmt.Errorf("%w: %q", ErrOwnAccount, username)
	}
	perms, err := rolePermissions(ctx, tx, role)
	if err != nil {
		return err
	}
	if err := a.mustHold(perms); err != nil {
		return fmt.Errorf("%w: %q: %w", ErrStrongerUser, username, err)
	}
	return nil
}

func roleHoldsAllPermissions(ctx context.Context, tx pgx.Tx, role string) (bool, error) {
	var all bool
	if err := tx.QueryRow(ctx, `SELECT `+fmt.Sprintf(holdsAllPermissions, "$1"), role).Scan(&all); err != nil {
		return false, fmt.Errorf("check permissions of role %q: %w", role, err)
	}
	return all, nil
}

func lockUserForAdminChange(ctx context.Context, tx pgx.Tx, username string) (lockedUser, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, adminLockKey); err != nil {
		return lockedUser{}, fmt.Errorf("lock admin set: %w", err)
	}
	var u lockedUser
	err := tx.QueryRow(ctx, `SELECT id, role, disabled, `+fmt.Sprintf(holdsAllPermissions, "u.role")+`
		FROM users u WHERE username = $1 FOR UPDATE OF u`, username).
		Scan(&u.id, &u.role, &u.disabled, &u.allPerms)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedUser{}, fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}
	if err != nil {
		return lockedUser{}, fmt.Errorf("load user %q: %w", username, err)
	}
	return u, nil
}

func ensureOtherAdmin(ctx context.Context, tx pgx.Tx) error {
	var admins int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users u WHERE NOT disabled AND `+fmt.Sprintf(holdsAllPermissions, "u.role")).Scan(&admins); err != nil {
		return fmt.Errorf("count admins: %w", err)
	}
	if admins <= 1 {
		return ErrLastAdmin
	}
	return nil
}
