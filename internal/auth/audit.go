package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	auditLogin       = "login"
	auditLoginFailed = "login_failed"
	auditLogout      = "logout"
	auditUserCreate  = "user.create"
	auditUserUpdate  = "user.update"
	auditUserDelete  = "user.delete"
	auditUserPass    = "user.password"
	auditUserDisable = "user.disable"
	auditUserEnable  = "user.enable"
	auditRoleCreate  = "role.create"
	auditRoleUpdate  = "role.update"
	auditRoleDelete  = "role.delete"
)

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func writeAudit(ctx context.Context, db execer, actor, action, target, addr string) error {
	if _, err := db.Exec(ctx, `INSERT INTO audit_log (actor, action, target, address) VALUES ($1, $2, $3, $4)`,
		actor, action, target, addr); err != nil {
		return fmt.Errorf("write audit %s: %w", action, err)
	}
	return nil
}

type AuditEntry struct {
	ID      int64
	At      time.Time
	Actor   string
	Action  string
	Target  string
	Address string
}

type AuditFilter struct {
	Actor  string
	Action string
	Target string
	Since  time.Time
	Until  time.Time
}

func (s *Service) ListAudit(ctx context.Context, f AuditFilter, offset, limit int) ([]AuditEntry, int, error) {
	if offset < 0 || limit <= 0 {
		return nil, 0, errors.New("list audit: offset must not be negative and limit must be positive")
	}
	var conds []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if f.Actor != "" {
		add("actor = $%d", f.Actor)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.Target != "" {
		add("target = $%d", f.Target)
	}
	if !f.Since.IsZero() {
		add("at >= $%d", f.Since)
	}
	if !f.Until.IsZero() {
		add("at < $%d", f.Until)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	var total int
	if err := s.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_log`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit: %w", err)
	}
	args = append(args, offset, limit)
	rows, err := s.store.Pool.Query(ctx, fmt.Sprintf(`SELECT id, at, actor, action, target, address FROM audit_log%s
		ORDER BY at DESC, id DESC OFFSET $%d LIMIT $%d`, where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit: %w", err)
	}
	entries, err := pgx.CollectRows(rows, pgx.RowToStructByPos[AuditEntry])
	if err != nil {
		return nil, 0, fmt.Errorf("list audit: %w", err)
	}
	return entries, total, nil
}

func (s *Service) ListAuditActions(ctx context.Context) ([]string, error) {
	rows, err := s.store.Pool.Query(ctx, `SELECT DISTINCT action FROM audit_log ORDER BY action`)
	if err != nil {
		return nil, fmt.Errorf("list audit actions: %w", err)
	}
	actions, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("list audit actions: %w", err)
	}
	return actions, nil
}
