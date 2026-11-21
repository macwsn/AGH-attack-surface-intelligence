package inventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func validStatusOverride(s string) bool {
	switch Status(s) {
	case "", StatusActive, StatusUnstable, StatusInactive:
		return true
	}
	return false
}

func (inv *Inventory) UpdateHostUserFields(ctx context.Context, address string, f HostUserFields) error {
	addr, err := normalizeAddress(address)
	if err != nil {
		return err
	}
	if !validStatusOverride(f.StatusOverride) {
		return fmt.Errorf("inventory: invalid status override %q", f.StatusOverride)
	}
	notes, err := inv.sealString(f.Notes)
	if err != nil {
		return err
	}
	tag, err := inv.db.Pool.Exec(ctx, `UPDATE hosts SET tags = $2, notes = $3, display_name = $4, owner = $5,
			criticality = $6, status_override = $7, user_updated_at = now()
		WHERE address = $1`, addr, nonNil(f.Tags), notes, f.DisplayName, f.Owner, f.Criticality, f.StatusOverride)
	if err != nil {
		return fmt.Errorf("update user fields of host %s: %w", addr, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrUnknownHost, addr)
	}
	return nil
}

func (inv *Inventory) GetHostUserFields(ctx context.Context, address string) (HostUserFields, error) {
	addr, err := normalizeAddress(address)
	if err != nil {
		return HostUserFields{}, err
	}
	var (
		f     HostUserFields
		notes []byte
	)
	err = inv.db.Pool.QueryRow(ctx, `SELECT tags, notes, display_name, owner, criticality, status_override
		FROM hosts WHERE address = $1`, addr).Scan(&f.Tags, &notes, &f.DisplayName, &f.Owner, &f.Criticality, &f.StatusOverride)
	if errors.Is(err, pgx.ErrNoRows) {
		return HostUserFields{}, fmt.Errorf("%w: %s", ErrUnknownHost, addr)
	}
	if err != nil {
		return HostUserFields{}, fmt.Errorf("read user fields of host %s: %w", addr, err)
	}
	if f.Notes, err = inv.openString(notes); err != nil {
		return HostUserFields{}, fmt.Errorf("host %s notes: %w", addr, err)
	}
	f.Tags = nonNil(f.Tags)
	return f, nil
}
