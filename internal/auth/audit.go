package auth

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	auditLogin       = "login"
	auditLoginFailed = "login_failed"
	auditLogout      = "logout"
	auditUserCreate  = "user.create"
	auditUserUpdate  = "user.update"
	auditUserDelete  = "user.delete"
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
