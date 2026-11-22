package inventory

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func (inv *Inventory) DeleteHost(ctx context.Context, e Editor, address string) error {
	addr, err := normalizeAddress(address)
	if err != nil {
		return err
	}
	return inv.db.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM hosts WHERE address = $1`, addr)
		if err != nil {
			return fmt.Errorf("delete host %s: %w", addr, err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s", ErrUnknownHost, addr)
		}
		return writeAudit(ctx, tx, e, "host.delete", addr)
	})
}

func (inv *Inventory) DeleteService(ctx context.Context, e Editor, address string, port int, protocol string) error {
	addr, err := normalizeAddress(address)
	if err != nil {
		return err
	}
	target := fmt.Sprintf("%s:%d/%s", addr, port, protocol)
	return inv.db.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM services s USING hosts h
			WHERE s.host_id = h.id AND h.address = $1 AND s.port = $2 AND s.protocol = $3`, addr, port, protocol)
		if err != nil {
			return fmt.Errorf("delete service %s: %w", target, err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s", ErrUnknownService, target)
		}
		return writeAudit(ctx, tx, e, "service.delete", target)
	})
}

func (inv *Inventory) Audit(ctx context.Context, e Editor, action, target string) error {
	return writeAudit(ctx, inv.db.Pool, e, action, target)
}

func writeAudit(ctx context.Context, db execer, e Editor, action, target string) error {
	if _, err := db.Exec(ctx, `INSERT INTO audit_log (actor, action, target, address) VALUES ($1, $2, $3, $4)`,
		e.Username, action, target, e.Addr); err != nil {
		return fmt.Errorf("audit %s of %s: %w", action, target, err)
	}
	return nil
}
