package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (s *Service) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := s.store.Pool.Query(ctx, `
		SELECT r.name, r.builtin,
		       COALESCE(array_agg(rp.permission ORDER BY rp.permission) FILTER (WHERE rp.permission IS NOT NULL), '{}')
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role = r.name
		GROUP BY r.name, r.builtin
		ORDER BY r.builtin DESC, r.name`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	roles, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Role, error) {
		var r Role
		var perms []string
		if err := row.Scan(&r.Name, &r.Builtin, &perms); err != nil {
			return Role{}, err
		}
		r.Permissions = make([]Permission, len(perms))
		for i, p := range perms {
			r.Permissions[i] = Permission(p)
		}
		return r, nil
	})
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return roles, nil
}

func (s *Service) CreateRole(ctx context.Context, actor Actor, name string, perms []Permission) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("create role: name must not be empty")
	}
	perms, err := checkPermissions(perms)
	if err != nil {
		return err
	}
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO roles (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`, name)
		if err != nil {
			return fmt.Errorf("create role %q: %w", name, err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %q", ErrRoleExists, name)
		}
		if err := insertRolePermissions(ctx, tx, name, perms); err != nil {
			return err
		}
		return writeAudit(ctx, tx, actor.Username, auditRoleCreate, name, actor.Addr)
	})
}

func (s *Service) UpdateRole(ctx context.Context, actor Actor, name string, perms []Permission) error {
	perms, err := checkPermissions(perms)
	if err != nil {
		return err
	}
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := lockCustomRole(ctx, tx, name); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role = $1`, name); err != nil {
			return fmt.Errorf("update role %q: %w", name, err)
		}
		if err := insertRolePermissions(ctx, tx, name, perms); err != nil {
			return err
		}
		return writeAudit(ctx, tx, actor.Username, auditRoleUpdate, name, actor.Addr)
	})
}

func (s *Service) DeleteRole(ctx context.Context, actor Actor, name string) error {
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := lockCustomRole(ctx, tx, name); err != nil {
			return err
		}
		var inUse bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE role = $1)`, name).Scan(&inUse); err != nil {
			return fmt.Errorf("check role %q in use: %w", name, err)
		}
		if inUse {
			return fmt.Errorf("%w: %q", ErrRoleInUse, name)
		}
		_, err := tx.Exec(ctx, `DELETE FROM roles WHERE name = $1`, name)
		if isPgError(err, pgForeignKeyViolation) {
			return fmt.Errorf("%w: %q", ErrRoleInUse, name)
		}
		if err != nil {
			return fmt.Errorf("delete role %q: %w", name, err)
		}
		return writeAudit(ctx, tx, actor.Username, auditRoleDelete, name, actor.Addr)
	})
}

func checkPermissions(perms []Permission) ([]Permission, error) {
	out := make([]Permission, 0, len(perms))
	for _, p := range perms {
		if !slices.Contains(AllPermissions, p) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownPermission, p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func lockCustomRole(ctx context.Context, tx pgx.Tx, name string) error {
	var builtin bool
	err := tx.QueryRow(ctx, `SELECT builtin FROM roles WHERE name = $1 FOR UPDATE`, name).Scan(&builtin)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %q", ErrUnknownRole, name)
	}
	if err != nil {
		return fmt.Errorf("load role %q: %w", name, err)
	}
	if builtin {
		return fmt.Errorf("%w: %q", ErrBuiltinRole, name)
	}
	return nil
}

func insertRolePermissions(ctx context.Context, tx pgx.Tx, role string, perms []Permission) error {
	for _, p := range perms {
		if _, err := tx.Exec(ctx, `INSERT INTO role_permissions (role, permission) VALUES ($1, $2)`, role, string(p)); err != nil {
			return fmt.Errorf("grant %s to role %q: %w", p, role, err)
		}
	}
	return nil
}
